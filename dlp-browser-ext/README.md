# DLP Upload Guard — browser extension (Tier 2, channel ④)

An MV3 Chrome/Edge extension that gives the DLP agent **content visibility on the
web-upload channel** — the TLS-blind spot of the network filter (WFP). It scans
files and text on their way into a web upload, asks the local `dlp-agent` native
host for a verdict, and blocks sensitive-data egress before the payload leaves the
browser.

This directory is the **extension + native-host registration only**. The scanning
itself is done by the Rust `dlp-agent browser-host` subcommand (a separate task).

> Built and structure-checked here. **NOT run in a browser.** True end-to-end
> verification requires a real Chrome/Edge install and the built `dlp-agent.exe` —
> that step is **manual** (operator, real browser).

---

## What it covers (and what it does not)

**Covers** — the web-upload vectors named in the plan (§3):

- `<input type="file">` selection (change events) — including inside forms.
- Drag-and-drop of files onto a page.
- Paste of text into a page.
- Programmatic uploads via `fetch()` / `XMLHttpRequest` whose body is a
  `File` / `Blob` / `FormData` (the common webmail + cloud-web-UI path). Hooked in
  the page's own JS realm by `inject.js` because MV3 `webRequest` **cannot** block
  request bodies.

**Honest limits — this does NOT stop everything:**

- **Chrome and Edge only.** Firefox is a follow-on; Safari, other browsers,
  desktop apps, and Electron apps are out of scope for this extension.
- **These upload vectors only.** A page that captured its own copy of `fetch`
  before our hook ran, uploads from a Web Worker / Service Worker, WebRTC data
  channels, WebSocket streaming, or WASM/native transports can bypass the page
  hook. The network filter (WFP, separate task) is the backstop for destinations;
  this extension adds *content* visibility where WFP is TLS-blind.
- **The analog hole is not closed.** Screen-view over VNC/AnyDesk/RDP, a
  privileged/SYSTEM payload that unhooks the browser, and encrypted exfil to an
  *allowed* destination are **not** stopped by this or any endpoint DLP. This is
  defence-in-depth, layered with the WFP filter, remote-tool blocking, USB /
  clipboard / file controls, EDR, and least-privilege — **not** a guarantee that
  "nothing leaks."
- **Binary files ARE content-inspected (up to 4 MiB).** The browser sandboxes a
  picked file's disk *path*, but not its *content* — so for binary uploads
  (PDF/DOCX/XLSX/…) the extension reads the file's bytes and sends them
  (`scan_bytes`, base64) to the host, which runs the full `verdict_bytes` engine
  (extract → fingerprint). This is the endpoint-DLP / Purview-equivalent binary
  path. Caps/limits, stated honestly: content is read up to **4 MiB** (matching
  the host + kernel cap); a file larger than that is sent truncated (best-effort —
  structured formats like DOCX may not extract from a prefix). **Images still need
  OCR**, which is deferred, so an image upload is not content-matched. If the bytes
  can't be read at all, it falls back to name-only (`scan_file`).

---

## Fail-secure behaviour

Consistent with the project rule *"fail secure, not fail open"*: if the native
host is not installed, crashes, or times out, the extension applies a fail-secure
**block** verdict (constant `SCANNER_UNAVAILABLE_VERDICT` in `background.js`).

Trade-off, stated honestly: with the shipped default, uploads on a machine where
the host is **not yet installed will be blocked**. During a staged rollout an
operator may relax this to `warn` — that is **fail-open** on this channel and must
be a deliberate, documented decision, not the default.

---

## The pinned native-messaging protocol

Extension `background.js` ⇄ native host `com.dlp.browser_host` speak this exact
protocol (the Rust `browser-host` implements the other side; both must match):

- **Framing:** Chrome native messaging — a **4-byte little-endian length prefix**
  followed by UTF-8 JSON. `chrome.runtime.connectNative` handles the framing.
- **Request** (extension → host):
  ```json
  {"version":1,"kind":"scan_text"|"scan_bytes"|"scan_file","text":"...","path":"...","content_b64":"...","url":"...","origin":"...","id":1}
  ```
  `text` for `scan_text`; `content_b64` (base64 file bytes) + `path` (filename) for
  `scan_bytes` (real binary content inspection); `path` (name only) for the legacy
  `scan_file`.
- **Reply** (host → extension):
  ```json
  {"version":1,"id":1,"verdict":"allow"|"block"|"warn","reason":"...","match":{"title":"...","containment":0.42}}
  ```

The host maps a fingerprint verdict to `allow` / `block` / `warn` using policy
thresholds (mirroring the agent's `kguard::should_block` logic). This extension
does not carry thresholds; it trusts the host's verdict and enforces it.

---

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest. Background service worker + two content scripts (ISOLATED `content.js`, MAIN-world `inject.js`). Permissions: `nativeMessaging`, `scripting`; `host_permissions: <all_urls>`. |
| `background.js` | Owns the single `connectNative("com.dlp.browser_host")` port, speaks the pinned protocol, correlates requests by `id`, applies fail-secure on host loss. |
| `content.js` | ISOLATED world. Hooks file inputs / drag-drop / paste / form-submit, reads text prefixes, requests verdicts from the background, cancels blocked uploads, shows an in-page banner. Bridges the MAIN-world fetch/XHR hook. |
| `inject.js` | MAIN world. Wraps `fetch` / `XMLHttpRequest.send` to screen `File`/`Blob`/`FormData` bodies and abort on a block verdict. |
| `nativehost/com.dlp.browser_host.json` | Native messaging host manifest template (path + `allowed_origins` with the extension-id placeholder). |
| `install-native-host.ps1` | Writes the launcher `.cmd`, materialises the host manifest, and registers it under Chrome + Edge `NativeMessagingHosts` (HKCU or HKLM). |

---

## Install (operator / manual)

1. Build the agent and place `dlp-agent.exe` at e.g. `C:\Program Files\DLP\`.
2. Load / package the extension and note its 32-char id
   (`chrome://extensions` → Developer mode → Load unpacked, or a fixed id from
   your packing key).
3. Register the native host (per-user):
   ```powershell
   .\install-native-host.ps1 -ExtensionId <your-32-char-id>
   ```
   Add `-Scope Machine` (elevated) for all users, `-AgentExe <path>` if not the
   default. The script writes `dlp-browser-host.cmd` (a wrapper that runs
   `dlp-agent.exe browser-host`, because Chrome cannot pass the subcommand
   argument through the manifest `path`), fills in the host manifest, and adds the
   Chrome + Edge registry keys.
4. **Verify manually in a real browser** — pick/drag a known-sensitive file into a
   web upload and confirm the block + banner. Not verifiable without a browser.

### Enterprise force-install (recommended)

Do not rely on users loading the extension. Force-install it via policy so it
cannot be disabled:

- **Chrome:** `ExtensionInstallForcelist` (or `ExtensionSettings` with
  `installation_mode: force_installed`) —
  `HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist`, value
  `<extension-id>;<update-url>` (an on-prem/self-hosted update URL for
  air-gapped sites; the Chrome Web Store URL requires internet and is not
  appropriate for firewalled/air-gapped deployments).
- **Edge:** the equivalent
  `HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist`.

Pair with the native-host registration above (prefer `-Scope Machine`) via your
configuration-management tooling (GPO / Intune / SCCM).

---

## Verified here vs. manual

- **Verifiable here:** `manifest.json` is valid JSON and MV3-structured; the file
  set and native-host manifest are well-formed; the pinned protocol matches the
  Rust host contract.
- **Manual only (real browser + built agent):** the extension loading, the native
  host launching, and any upload being blocked end-to-end. **Not claimed here.**
