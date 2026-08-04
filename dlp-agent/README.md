# DLP Windows Agent (Rust) — Phase 2: secure channel

The endpoint half of the on-premise DLP product. **Phase 2 scope is the secure
channel only** — enrollment, identity, and mutual-TLS check-in. There is **no DLP
enforcement yet** (USB/clipboard/upload interception is later); this is the
trusted body that detection features will attach to.

It does exactly what `dlp-management-server/scripts/fake-agent.js` proved, but as
production Rust: a real program that generates its own key, enrolls once, seals
its identity with the OS, and checks in over mTLS — fail-secure.

## What it does

| Step | Detail |
|---|---|
| **Key generation** | RSA-2048 key pair generated locally with a CSPRNG. The private key **never leaves the machine** — only the CSR (public key) is sent. |
| **Enrollment** | Presents the one-time token + CSR to `POST /agent/enroll`; receives a CA-signed certificate. The server assigns the identity (`dlp-agent-<id>`) — the CSR's requested name is ignored. |
| **CA pinning** | Trusts **only** the CA shipped with the installer (system roots disabled). Verifies the server on every connection, including enrollment — no counterfeit console, works air-gapped. |
| **Sealed identity** | The private key + certificate are sealed at rest with **DPAPI (machine scope)** on Windows — a stolen identity file can't be replayed on another PC. |
| **Check-in** | Mutual TLS to `POST /agent/checkin`: proves identity with the client cert, refreshes state on a timer. |
| **Fail-secure** | If the server is unreachable, the agent keeps running on cached state and retries — it never falls open. A retired agent is refused (`403`), i.e. server-side revocation. |

## Build

```bash
cargo build --release        # -> target/release/dlp-agent.exe
```

Pure-Rust crypto and TLS (rsa + x509-cert + rustls) — no OpenSSL, no C toolchain,
statically self-contained for deployment to locked-down PCs.

## Run (dev / testing)

Point it at a running management server. Export the server's CA
(`dlp-management-server/ca/ca-cert.pem`) and a token from the console.

```bash
export DLP_AGENT_SERVER_URL="https://localhost:8443"
export DLP_AGENT_TOKEN="dlpenr_…"          # from the console
export DLP_AGENT_CA_CERT="…/ca/ca-cert.pem"
export DLP_AGENT_STATE_DIR="./agent-state"

dlp-agent enroll     # enroll once, seal the identity
dlp-agent status     # show the stored identity
dlp-agent once       # a single mTLS check-in
dlp-agent run        # the fail-secure check-in loop
```

In production, configuration comes from `C:\ProgramData\DLPAgent\agent.toml`
(see `agent.example.toml`); env vars override it.

## Modules

```
src/config.rs     load config (TOML file + env overrides)
src/identity.rs   RSA keygen + PKCS#10 CSR
src/storage.rs    DPAPI-sealed identity + cached state
src/client.rs     CA-pinned mTLS clients (enroll: no cert; check-in: client cert)
src/enroll.rs     the enrollment handshake
src/checkin.rs    the mTLS heartbeat
src/main.rs       modes: enroll | once | run | status
```

## Not done yet (next steps)

- **Windows service wrapper** — run under the SCM (start at boot, run as SYSTEM),
  logging to the Windows event log. (`windows-service` dependency is staged.)
- **MSI packaging** (WiX) — takes `SERVER` + `TOKEN` install properties, drops the
  config + CA, installs the service; deployable via Group Policy / SCCM / Intune
  in staged rings.
- Later phases: certificate auto-renewal, the entitlement token (Phase 3), and
  eventually the actual DLP enforcement engine.
