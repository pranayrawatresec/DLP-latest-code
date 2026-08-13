// DLP Upload Guard — background service worker.
//
// Owns the single connection to the native messaging host and speaks the
// PINNED native-messaging protocol (see README.md and tier2-plan.md §3).
// Content scripts cannot talk to a native host directly, so they send scan
// requests here via chrome.runtime.sendMessage and receive the verdict back.
//
// PINNED protocol (both sides MUST match — do not change unilaterally):
//   Framing:  Chrome native messaging (4-byte LE length prefix + UTF-8 JSON).
//             chrome.runtime.connectNative handles the framing for us.
//   Request  (ext -> host): {"version":1,"kind":"scan_text"|"scan_file",
//                            "text"?:string,"path"?:string,"url":string,
//                            "origin":string,"id":number}
//   Reply    (host -> ext): {"version":1,"id":number,
//                            "verdict":"allow"|"block"|"warn","reason"?:string,
//                            "match"?:{"title":string,"containment":number}}

'use strict';

const NATIVE_HOST = 'com.dlp.browser_host';
const PROTOCOL_VERSION = 1;

// How long we wait for the host to answer before treating it as unavailable.
const SCAN_TIMEOUT_MS = 8000;

// FAIL-SECURE POLICY (project non-negotiable: "fail secure, not fail open").
// If the native host is not installed / crashes / times out, what verdict do
// we return? Default 'block' honours fail-secure: no upload proceeds unscanned.
//
// HONEST TRADE-OFF: with 'block', every upload on a machine where the host is
// not yet installed will be blocked. During a staged rollout an operator may
// relax this to 'warn' (allow-with-warning) — that is FAIL-OPEN on this channel
// and must be a deliberate, documented decision. It is NOT the shipped default.
const SCANNER_UNAVAILABLE_VERDICT = 'block';

let nativePort = null;
let nextRequestId = 1;
const pending = new Map(); // id -> { resolve, timer }

function connectNative() {
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST);
  } catch (e) {
    console.warn('[dlp] connectNative threw:', e);
    nativePort = null;
    return null;
  }

  nativePort.onMessage.addListener((msg) => {
    if (!msg || typeof msg.id !== 'number') return;
    const entry = pending.get(msg.id);
    if (!entry) return;
    clearTimeout(entry.timer);
    pending.delete(msg.id);
    entry.resolve(normalizeReply(msg));
  });

  nativePort.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    console.warn('[dlp] native host disconnected:', err && err.message);
    nativePort = null;
    // Fail every in-flight request fail-secure.
    for (const [id, entry] of pending) {
      clearTimeout(entry.timer);
      entry.resolve(unavailableReply(id, err && err.message));
    }
    pending.clear();
  });

  return nativePort;
}

function normalizeReply(msg) {
  let verdict = msg.verdict;
  if (verdict !== 'allow' && verdict !== 'block' && verdict !== 'warn') {
    // Unknown/garbled verdict from host -> fail-secure.
    verdict = SCANNER_UNAVAILABLE_VERDICT;
  }
  return {
    verdict: verdict,
    reason: typeof msg.reason === 'string' ? msg.reason : undefined,
    match: msg.match && typeof msg.match === 'object' ? msg.match : undefined,
  };
}

function unavailableReply(_id, detail) {
  return {
    verdict: SCANNER_UNAVAILABLE_VERDICT,
    reason:
      'DLP scanner unavailable' +
      (detail ? ' (' + detail + ')' : '') +
      ' — fail-secure verdict applied',
    match: undefined,
  };
}

// Send one scan request to the native host and resolve with the verdict.
// `req` is { kind, text?, path?, url, origin }.
function scan(req) {
  return new Promise((resolve) => {
    if (!nativePort) {
      connectNative();
    }
    if (!nativePort) {
      resolve(unavailableReply(-1, 'host not reachable'));
      return;
    }

    const id = nextRequestId++;
    const wire = {
      version: PROTOCOL_VERSION,
      kind: req.kind,
      url: String(req.url || ''),
      origin: String(req.origin || ''),
      id: id,
    };
    if (req.kind === 'scan_text') {
      wire.text = typeof req.text === 'string' ? req.text : '';
    } else if (req.kind === 'scan_bytes') {
      // Binary upload: forward the filename (format detection) + the file's
      // base64 bytes so the host content-inspects it (verdict_bytes).
      wire.path = typeof req.path === 'string' ? req.path : '';
      wire.content_b64 = typeof req.content_b64 === 'string' ? req.content_b64 : '';
    } else {
      // scan_file (legacy name-only)
      wire.path = typeof req.path === 'string' ? req.path : '';
    }

    const timer = setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        resolve(unavailableReply(id, 'timeout'));
      }
    }, SCAN_TIMEOUT_MS);

    pending.set(id, { resolve, timer });

    try {
      nativePort.postMessage(wire);
    } catch (e) {
      clearTimeout(timer);
      pending.delete(id);
      resolve(unavailableReply(id, e && e.message));
    }
  });
}

// Content scripts ask us to scan. We answer asynchronously (return true to keep
// the sendResponse channel open).
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== 'dlp-scan') return false;
  scan(message.req).then((verdict) => sendResponse(verdict));
  return true;
});

// Warm the connection at startup so the first upload isn't slowed by a
// cold host launch. Harmless if the host isn't installed (we just retry lazily).
connectNative();
