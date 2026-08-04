// DLP Upload Guard — content script (ISOLATED world).
//
// Runs on every page/frame. Detects the web-upload vectors the plan names
// (file <input>, drag-drop, paste) and — via the MAIN-world hook in inject.js —
// fetch()/XMLHttpRequest bodies. Extracts metadata + readable text, asks the
// background worker for a verdict over the PINNED native-messaging protocol,
// and on "block" cancels the upload / form submit and warns the user in-page.
//
// It never reads binary file bytes for transport: text-like files are read as
// text (scan_text); everything else is scanned by name only (scan_file). See
// README.md "Honest limits".

'use strict';

// --- config ---------------------------------------------------------------

// Read at most this many bytes of a text-like file into the scan_text request.
const MAX_TEXT_BYTES = 1024 * 1024; // 1 MiB

// Extensions we treat as text and read inline. Everything else -> scan_file
// (name only). This is deliberately conservative.
const TEXT_EXTENSIONS = new Set([
  'txt', 'text', 'csv', 'tsv', 'log', 'md', 'markdown', 'json', 'xml', 'yaml',
  'yml', 'html', 'htm', 'rtf', 'ini', 'conf', 'cfg', 'sql', 'js', 'ts', 'py',
  'java', 'c', 'h', 'cpp', 'cs', 'go', 'rs', 'sh', 'ps1', 'bat',
]);

// --- verdict plumbing -----------------------------------------------------

function extOf(name) {
  const i = String(name || '').lastIndexOf('.');
  return i >= 0 ? name.slice(i + 1).toLowerCase() : '';
}

function isTextLike(file) {
  if (file.type && file.type.startsWith('text/')) return true;
  if (file.type === 'application/json' || file.type === 'application/xml') return true;
  return TEXT_EXTENSIONS.has(extOf(file.name));
}

function readTextPrefix(file) {
  return new Promise((resolve) => {
    try {
      const slice = file.slice(0, MAX_TEXT_BYTES);
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ''));
      reader.onerror = () => resolve('');
      reader.readAsText(slice);
    } catch (_e) {
      resolve('');
    }
  });
}

// Ask the background worker (which owns the native host) for a verdict.
function requestVerdict(req) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: 'dlp-scan', req }, (resp) => {
        if (chrome.runtime.lastError || !resp) {
          // Extension context invalidated / worker gone -> fail-secure.
          resolve({ verdict: 'block', reason: 'DLP scanner unreachable (fail-secure)' });
          return;
        }
        resolve(resp);
      });
    } catch (_e) {
      resolve({ verdict: 'block', reason: 'DLP scanner unreachable (fail-secure)' });
    }
  });
}

// Scan a single File object. Returns a verdict object.
async function scanFile(file, url, origin) {
  if (isTextLike(file)) {
    const text = await readTextPrefix(file);
    return requestVerdict({ kind: 'scan_text', text, url, origin });
  }
  // Browsers sandbox the real filesystem path; we can only forward the name.
  // The host scans by name (best effort). Honest limit — see README.
  return requestVerdict({ kind: 'scan_file', path: file.name, url, origin });
}

// Scan raw text (paste / text form field). Returns a verdict object.
function scanText(text, url, origin) {
  return requestVerdict({ kind: 'scan_text', text, url, origin });
}

// --- user notification (in-page banner) -----------------------------------

let bannerEl = null;
let bannerTimer = null;

function showBanner(text, level) {
  try {
    if (!bannerEl) {
      bannerEl = document.createElement('div');
      bannerEl.setAttribute('data-dlp-banner', '1');
      bannerEl.style.cssText = [
        'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
        'font:14px/1.4 system-ui,Segoe UI,Arial,sans-serif',
        'padding:10px 16px', 'color:#fff', 'text-align:center',
        'box-shadow:0 2px 6px rgba(0,0,0,.3)', 'pointer-events:none',
      ].join(';');
    }
    bannerEl.style.background = level === 'block' ? '#b00020' : '#8a6d00';
    bannerEl.textContent = text;
    if (document.documentElement && !bannerEl.isConnected) {
      document.documentElement.appendChild(bannerEl);
    }
    clearTimeout(bannerTimer);
    bannerTimer = setTimeout(() => {
      if (bannerEl && bannerEl.isConnected) bannerEl.remove();
    }, 8000);
  } catch (_e) {
    // DOM not ready / restricted — best effort only.
  }
}

function verdictText(v) {
  const t = v && v.match && v.match.title ? ' — matched: ' + v.match.title : '';
  const r = v && v.reason ? ' (' + v.reason + ')' : '';
  return t + r;
}

// --- upload-vector hooks ---------------------------------------------------

// Track file inputs that most recently produced a BLOCK so a later form submit
// can be cancelled even if the change handler already returned.
const blockedInputs = new WeakSet();
// Inputs with a scan still in flight — block submit until they resolve.
const pendingInputs = new WeakSet();

function pageUrl() {
  try { return location.href; } catch (_e) { return ''; }
}
function pageOrigin() {
  try { return location.origin; } catch (_e) { return ''; }
}

// 1) file <input> change
document.addEventListener(
  'change',
  async (ev) => {
    const el = ev.target;
    if (!el || el.tagName !== 'INPUT' || el.type !== 'file') return;
    if (!el.files || el.files.length === 0) return;

    const files = Array.from(el.files);
    pendingInputs.add(el);
    blockedInputs.delete(el);

    let blocked = false;
    let worstReason = '';
    for (const f of files) {
      const v = await scanFile(f, pageUrl(), pageOrigin());
      if (v.verdict === 'block') {
        blocked = true;
        worstReason = verdictText(v);
        break;
      } else if (v.verdict === 'warn' && !worstReason) {
        worstReason = verdictText(v);
        showBanner('DLP warning: this upload contains flagged content' + worstReason, 'warn');
      }
    }
    pendingInputs.delete(el);

    if (blocked) {
      blockedInputs.add(el);
      try { el.value = ''; } catch (_e) { /* readonly some frameworks */ }
      showBanner('DLP blocked this upload: sensitive data detected' + worstReason, 'block');
    }
  },
  true // capture
);

// 2) drag-drop onto the page
document.addEventListener(
  'drop',
  async (ev) => {
    const dt = ev.dataTransfer;
    if (!dt) return;
    const files = dt.files ? Array.from(dt.files) : [];
    if (files.length === 0) return;

    // We cannot synchronously know the drop target's intent, so scan and warn.
    for (const f of files) {
      const v = await scanFile(f, pageUrl(), pageOrigin());
      if (v.verdict === 'block') {
        // Best effort: cancel the drop if still cancelable.
        try { ev.preventDefault(); ev.stopPropagation(); } catch (_e) {}
        showBanner('DLP blocked a dropped file: sensitive data detected' + verdictText(v), 'block');
        break;
      } else if (v.verdict === 'warn') {
        showBanner('DLP warning on dropped file' + verdictText(v), 'warn');
      }
    }
  },
  true
);

// 3) paste of text into the page
document.addEventListener(
  'paste',
  async (ev) => {
    const cd = ev.clipboardData;
    if (!cd) return;
    const text = cd.getData('text/plain') || '';
    if (!text) return;
    const v = await scanText(text, pageUrl(), pageOrigin());
    if (v.verdict === 'block') {
      try { ev.preventDefault(); ev.stopPropagation(); } catch (_e) {}
      showBanner('DLP blocked paste: sensitive data detected' + verdictText(v), 'block');
    } else if (v.verdict === 'warn') {
      showBanner('DLP warning on pasted text' + verdictText(v), 'warn');
    }
  },
  true
);

// 4) form submit — cancel if any file input in the form was blocked or is still
//    being scanned.
document.addEventListener(
  'submit',
  (ev) => {
    const form = ev.target;
    if (!form || form.tagName !== 'FORM') return;
    let inputs;
    try {
      inputs = form.querySelectorAll('input[type=file]');
    } catch (_e) {
      return;
    }
    for (const el of inputs) {
      if (blockedInputs.has(el)) {
        ev.preventDefault();
        ev.stopPropagation();
        showBanner('DLP blocked form submission: it includes a blocked file', 'block');
        return;
      }
      if (pendingInputs.has(el)) {
        ev.preventDefault();
        ev.stopPropagation();
        showBanner('DLP is still scanning an attached file — submission held', 'warn');
        return;
      }
    }
  },
  true
);

// 5) fetch()/XHR bodies — the MAIN-world hook (inject.js) posts upload metadata
//    here and awaits our verdict via window.postMessage. We answer with the same
//    id so inject.js can allow/abort the request.
window.addEventListener('message', async (ev) => {
  if (ev.source !== window) return;
  const d = ev.data;
  if (!d || d.__dlp !== 'req' || typeof d.id !== 'number') return;

  let verdict;
  if (d.kind === 'scan_text') {
    verdict = await scanText(String(d.text || ''), pageUrl(), pageOrigin());
  } else {
    verdict = await requestVerdict({
      kind: 'scan_file',
      path: String(d.name || ''),
      url: pageUrl(),
      origin: pageOrigin(),
    });
  }

  if (verdict.verdict === 'block') {
    showBanner('DLP blocked a network upload: sensitive data detected' + verdictText(verdict), 'block');
  } else if (verdict.verdict === 'warn') {
    showBanner('DLP warning on a network upload' + verdictText(verdict), 'warn');
  }

  window.postMessage({ __dlp: 'res', id: d.id, verdict: verdict.verdict, reason: verdict.reason }, '*');
});
