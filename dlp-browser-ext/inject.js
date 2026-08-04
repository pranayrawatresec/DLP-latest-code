// DLP Upload Guard — page hook (MAIN world).
//
// Runs in the page's own JS realm so it can wrap fetch()/XMLHttpRequest. When a
// request carries a File/Blob/FormData body (a programmatic upload — the common
// path for webmail and cloud web UIs), it extracts metadata + readable text and
// asks content.js (ISOLATED world) for a verdict via window.postMessage. On a
// "block" verdict it aborts the request so the payload never leaves the browser.
//
// It talks ONLY to content.js in this extension (same-window postMessage, tagged
// __dlp). It never reads network responses and never logs bodies.
//
// HONEST LIMIT: this covers fetch/XHR that this hook can see. A page that uses
// its own bundled copy captured before us, a worker/service-worker upload, or a
// WASM/native transport can bypass it. True coverage needs a real browser test
// (manual). MV3 webRequest cannot block request bodies, which is why we hook here.

(function () {
  'use strict';

  if (window.__dlpHooked) return;
  window.__dlpHooked = true;

  const MAX_TEXT_BYTES = 1024 * 1024;
  const VERDICT_TIMEOUT_MS = 8000;

  let seq = 1;
  const waiters = new Map(); // id -> resolve

  window.addEventListener('message', (ev) => {
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d || d.__dlp !== 'res' || typeof d.id !== 'number') return;
    const resolve = waiters.get(d.id);
    if (resolve) {
      waiters.delete(d.id);
      resolve({ verdict: d.verdict, reason: d.reason });
    }
  });

  // Ask content.js for a verdict; fail-secure to "block" on timeout.
  function askVerdict(payload) {
    return new Promise((resolve) => {
      const id = seq++;
      waiters.set(id, resolve);
      const t = setTimeout(() => {
        if (waiters.has(id)) {
          waiters.delete(id);
          resolve({ verdict: 'block', reason: 'DLP scan timeout (fail-secure)' });
        }
      }, VERDICT_TIMEOUT_MS);
      const done = (v) => { clearTimeout(t); resolve(v); };
      waiters.set(id, done);
      window.postMessage(Object.assign({ __dlp: 'req', id }, payload), '*');
    });
  }

  function extIsText(name) {
    return /\.(txt|text|csv|tsv|log|md|markdown|json|xml|ya?ml|html?|rtf|ini|conf|cfg|sql|js|ts|py|java|c|h|cpp|cs|go|rs|sh|ps1|bat)$/i.test(
      String(name || '')
    );
  }
  function isTextLike(blob, name) {
    if (blob && blob.type && blob.type.indexOf('text/') === 0) return true;
    if (blob && (blob.type === 'application/json' || blob.type === 'application/xml')) return true;
    return extIsText(name);
  }

  async function readTextPrefix(blob) {
    try {
      const slice = blob.slice(0, MAX_TEXT_BYTES);
      if (slice.text) return await slice.text();
      return await new Response(slice).text();
    } catch (_e) {
      return '';
    }
  }

  // Collect scannable parts (File/Blob) from a request body. Returns an array of
  // { blob, name }.
  function partsFromBody(body) {
    const parts = [];
    if (!body) return parts;
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      for (const [, val] of body.entries()) {
        if (val && typeof val === 'object' && 'size' in val) {
          parts.push({ blob: val, name: val.name || 'form-blob' });
        }
      }
    } else if (typeof File !== 'undefined' && body instanceof File) {
      parts.push({ blob: body, name: body.name || 'file' });
    } else if (typeof Blob !== 'undefined' && body instanceof Blob) {
      parts.push({ blob: body, name: 'blob' });
    }
    return parts;
  }

  // Returns the first blocking verdict, or null if all clear.
  async function screenParts(parts) {
    for (const p of parts) {
      let payload;
      if (isTextLike(p.blob, p.name)) {
        payload = { kind: 'scan_text', text: await readTextPrefix(p.blob) };
      } else {
        payload = { kind: 'scan_file', name: p.name };
      }
      const v = await askVerdict(payload);
      if (v && v.verdict === 'block') return v;
    }
    return null;
  }

  // --- wrap fetch ---------------------------------------------------------
  const realFetch = window.fetch;
  if (typeof realFetch === 'function') {
    window.fetch = async function (input, init) {
      try {
        let body = init && init.body;
        if (!body && input && typeof input === 'object' && 'body' in input) {
          // Request object; body is a stream we won't drain — skip.
          body = null;
        }
        const parts = partsFromBody(body);
        if (parts.length > 0) {
          const blocked = await screenParts(parts);
          if (blocked) {
            const reason = blocked.reason || 'sensitive data detected';
            return Promise.reject(new DOMException('Upload blocked by DLP: ' + reason, 'AbortError'));
          }
        }
      } catch (_e) {
        // Never let the hook break the page; on internal error, fall through.
      }
      return realFetch.apply(this, arguments);
    };
  }

  // --- wrap XMLHttpRequest.send ------------------------------------------
  const XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype && typeof XHR.prototype.send === 'function') {
    const realSend = XHR.prototype.send;
    XHR.prototype.send = function (body) {
      const parts = partsFromBody(body);
      if (parts.length === 0) {
        return realSend.apply(this, arguments);
      }
      const xhr = this;
      const args = arguments;
      screenParts(parts)
        .then((blocked) => {
          if (blocked) {
            try { xhr.abort(); } catch (_e) {}
            try {
              xhr.dispatchEvent(new Event('error'));
            } catch (_e) {}
            return;
          }
          realSend.apply(xhr, args);
        })
        .catch(() => {
          // On internal error, do not silently allow: fail-secure -> abort.
          try { xhr.abort(); } catch (_e) {}
        });
    };
  }
})();
