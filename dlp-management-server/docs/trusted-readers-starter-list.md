# Trusted-reader allowlist — starter list & curation guide

The **trusted-reader allowlist** is the set of applications permitted to *read*
sensitive content locally on an endpoint. With read-deny enabled, every process
that does **not** match an allowlist entry is treated as an untrusted reader and
the kernel minifilter denies it the read of in-scope sensitive files.

An **empty** allowlist (or a `central`-authority list with no entries) means
*nothing* is trusted — the machine is unusable the moment protection turns on,
because even the app that owns a file (Word opening its own `.docx`) is denied.
Migration `015_seed_starter_trusted_readers.sql` therefore ships a safe baseline;
this guide explains it and how to curate the rest.

## What ships by default (migration 015, global scope)

| Type | Value | Covers |
|---|---|---|
| publisher | `Microsoft Windows` | The OS: Explorer, Notepad/WordPad, Photos, the search indexer, inbox apps |
| publisher | `Microsoft Corporation` | Office, **Edge (browser + built-in PDF viewer)**, Teams, OneDrive, **Microsoft Defender (AV)** |
| publisher | `Microsoft Windows Publisher` | Inbox/Store components and system tooling |
| path | `C:\Program Files\DLP Agent` | The DLP agent's own install tree |

On a Microsoft-centric endpoint this baseline already covers the **browser**,
**PDF viewer**, and **antivirus** (all Edge/Defender). The seed is idempotent
(`ON CONFLICT DO NOTHING`) and **never overwrites** an entry an admin already
added — re-running migrations is safe.

## Why publisher rules (and the match order)

The agent decides an application's identity in priority order **publisher →
path → name**:

- **`publisher`** — the Authenticode **signer common-name (CN)**, e.g.
  `Microsoft Corporation`. Spoof-resistant: a renamed piece of malware cannot
  sign as Microsoft, so it can never inherit this trust. **Prefer this.**
- **`path`** — an image-path prefix, matched at a path-component boundary
  (`C:\Program Files\Adobe` matches `...\Adobe\Acrobat\...` but not
  `...\AdobeEvil`). Use for unsigned-but-trusted tools in a
  non-user-writable directory.
- **`name`** — the image base name (`winword.exe`). **Weakest** — anything
  renamed to that name is trusted. The console flags name rules with an amber
  caution. Avoid unless paired with app-control (WDAC/AppLocker).

## Vendors to enable per deployment (NOT seeded)

Add these from the console (Trusted Applications → Add) only if the site uses
them. Values are the current Authenticode signer CNs — **verify on your own
build** (signers change with corporate renames):

| App | Type | Value |
|---|---|---|
| Adobe Acrobat / Reader | publisher | `Adobe Inc.` (older builds: `Adobe Systems Incorporated`) |
| Google Chrome | publisher | `Google LLC` |
| Mozilla Firefox | publisher | `Mozilla Corporation` |
| 7-Zip | publisher | `Igor Pavlov` |
| Notepad++ | publisher | `Notepad++` |
| CrowdStrike (AV/EDR) | publisher | `CrowdStrike, Inc.` |
| SentinelOne (AV/EDR) | publisher | `Sentinel Labs, Inc.` |
| Symantec / Broadcom (AV) | publisher | `Broadcom Inc.` |
| Veeam (backup) | publisher | `Veeam Software Group GmbH` |
| Commvault (backup) | publisher | `Commvault Systems, Inc.` |
| Veritas / NetBackup (backup) | publisher | `Veritas Technologies LLC` |

### How to find the exact signer CN for an app

On a machine that has the app installed, in PowerShell:

```powershell
(Get-AuthenticodeSignature "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe").SignerCertificate.Subject
# CN=Adobe Inc., OU=Acrobat DC, O=Adobe Inc., L=San Jose, S=California, C=US, ...
```

Use the **CN=** value (`Adobe Inc.`) as the `publisher` rule value.

## Curation principles

1. **Least privilege.** Trust the specific apps a site actually uses, not broad
   categories. Every trusted reader is one more program allowed to pull
   sensitive bytes locally.
2. **Publisher over path over name.** Only drop to `path` for unsigned trusted
   tools in a protected directory; only drop to `name` with app-control backing.
3. **Scope with groups where it helps.** A reader can be global (every group) or
   scoped to one endpoint group — e.g. trust a niche engineering tool only for
   the engineering group, not the whole estate.
4. **Review periodically.** Remove apps that are decommissioned; the smaller the
   list, the smaller the local-read surface.
5. **The agent is self-trusted in the kernel** (its own I/O is skipped), so it
   does not strictly need an allowlist entry; the seeded path rule only covers
   auxiliary tooling shipped alongside it.
