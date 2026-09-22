# ML Document Classification — VM Deployment Runbook

**Goal:** stand the product up on a VM **with the 256 MB classifier inside it**, and prove
that a file gets a sensitivity answer from **both** detection signals — fingerprinting
(IDM/EDM) *and* the ONNX document classifier — including the case the model exists for:
a document nobody ever registered.

Builds on `ON-PREM-DEPLOYMENT-GUIDE.md` (server + endpoint) and `USB-DEMO-RUNBOOK.md`
(the VM, the driver, the enrollment flow). Nothing here replaces those; this adds the
model to a bench that already works.

> **Snapshot the VM first.** You will be replacing the agent binary and restarting the
> service. Nothing here touches the kernel driver — the classifier is entirely user-mode
> — but the rest of the bench is the same one the driver runbooks use.

---

## 0. The two signals — say this out loud before the demo

The product now answers "is this file sensitive?" with **two independent detectors**, and
the answer is **OR**, never AND:

- **Fingerprinting (IDM/EDM)** knows *exactly which registered document or which database
  row* is leaving. It is precise and forensic — it names the file and the matched
  passages. Its blind spot is total: a document that was never registered in the console
  is invisible to it. Most of the sensitive material on a real endpoint was never
  registered, because it was written this morning.
- **The classifier (ONNX, V6.2.01)** reads the extracted text and predicts one of **29
  business functions** (Finance, Nuclear & Strategic Systems, Intelligence, Legal…). An
  admin marks which of those functions are sensitive at this site. It has never seen the
  document before and does not need to. Its blind spot is the mirror image: it can say
  "this is a nuclear document", it can never say *which* nuclear document.

Each covers the other's blind spot, so the fused verdict is `fingerprint OR model`, and
the classifier can only ever **add** sensitivity — it never downgrades a fingerprint hit.
Both signals agreeing is `severity: critical`; fingerprint alone is `high`; the model
alone is `medium`.

---

## 1. Prerequisites

| Requirement | Why | Check |
|---|---|---|
| A working bench | The model is an addition, not a replacement. Server on `:8443` (agent mTLS) + `:3001` (console), agent enrolled, ideally a compiled index bundle. | `USB-DEMO-RUNBOOK.md` §1–2; `.\dlp-agent.exe status` shows an agent id |
| Agent build with `src/ml/` | The classifier is in the agent binary. An older `dlp-agent.exe` has no `classify` command. | `.\dlp-agent.exe classify --help` prints usage |
| Server with migration `021_ml_policy.sql` | The console page and `/agent/ml-policy` do not exist without it. | `npm run migrate` ends with 021 applied |
| **~300 MB free** on the VM | `model.onnx` alone is **268,023,580 bytes**. Add the sidecar (1,985 B), the tokenizer (466,062 B), ONNX Runtime (~18 MB) and headroom for the staging copy. | `Get-PSDrive C` |
| **ONNX Runtime** (`onnxruntime.dll`) | See below — this is the one prerequisite people miss. | §1.1 |
| RAM | The graph is memory-mapped; a 2 GB VM will thrash. 4 GB is comfortable. | — |

### 1.1 The ONNX Runtime question

`dlp-agent.exe` **does not link ONNX Runtime and does not download it at build time.**
That is a deliberate supply-chain decision (`ort` with `default-features = false`,
`load-dynamic`, `api-17` — the reasoning is written out at the top of
`dlp-agent/src/ml/engine.rs`): a defence build must be reproducible from a vendored tree
with the network unplugged, and a ~18 MB binary fetched during `cargo build` is an
artifact nobody signed off.

The consequence at deploy time: **the library has to come from somewhere, and you put it
there.** The agent `dlopen()`s it at first use, resolving in this order:

1. `<ml root>\runtime\onnxruntime.dll` — the shipped location. `<ml root>` is the parent
   of the directory holding `model.onnx`, so with the standard layout
   (`C:\dlp\model\model.onnx`) that is `C:\dlp\runtime\onnxruntime.dll`.
2. `%ORT_DYLIB_PATH%`.
3. the bare name `onnxruntime.dll`, which resolves next to `dlp-agent.exe` and then
   through the OS loader path.

**Production / air-gapped:** use (1) — one file, beside the model, re-signed and
inventoried with the rest of the agent payload. `stage-ml-model.ps1 -RuntimeDll` puts it
there.

**Getting the DLL for a lab VM** (do this on a connected box, then carry the file):

```powershell
python -m pip download onnxruntime --no-deps -d $env:TEMP\ort
# extract onnxruntime/capi/onnxruntime.dll from the .whl (it is a zip)
```

An existing `pip install onnxruntime` already has it at
`<site-packages>\onnxruntime\capi\onnxruntime.dll`.

If it is missing entirely, **nothing crashes**: the ML signal reports
`status: "unavailable"` and the egress channels apply `failBlock`. That is case (d) of
the demo, and it is worth showing on purpose.

---

## 2. Stage the model on the VM

Copy the whole `Document_classification\` package to the VM (or to a staging share the VM
can read) along with `scripts\stage-ml-model.ps1`, then run the script. It copies three
artifacts into the agent's model directory and **SHA-256 verifies every one of them
against the values in `Document_classification/README.md` §2 and
`deployment_manifest.json`**.

That verification is the whole point. A 256 MB file crossing a VM shared folder, an RDP
drive redirect or a USB stick is the one file in this product that plausibly arrives
truncated — and a truncated ONNX graph does not fail cleanly. It may still open, the
session may still build, and the agent then labels documents wrongly *in silence*. A NUC
document reported as ADM and allowed out is the failure this guards.

```powershell
# On the VM, elevated if InstallRoot is under Program Files.
powershell -ExecutionPolicy Bypass -File C:\stage\stage-ml-model.ps1 `
    -SourceRoot  'C:\stage\Document_classification' `
    -InstallRoot 'C:\dlp' `
    -RuntimeDll  'C:\stage\onnxruntime.dll' `
    -WhatIf                                  # dry run first — says what it would do
```

Drop `-WhatIf` to actually stage. Expected output:

```
Staging the V6.2.01 document classifier
  source:  C:\stage\Document_classification
  install: C:\dlp

1/3  Verifying the source package
  OK  model\model.onnx                           268023580 bytes  6bb36568c1e78256...
  OK  model\model.onnx.json                           1985 bytes  4c37bfa10feec6a1...
  OK  backbone\tokenizer.json                       466062 bytes  ce64fce797c24f68...

2/3  Staging into C:\dlp
  OK  model\model.onnx                           268023580 bytes  verified
  OK  model\model.onnx.json                           1985 bytes  verified
  OK  model\tokenizer.json                          466062 bytes  verified

3/3  ONNX Runtime
  OK  runtime\onnxruntime.dll        <n> bytes  version <x.y.z>

Staged 3 artifact(s), 0 already correct. All SHA-256 verified.
```

**Any hash mismatch is fatal and the script deletes the bad copy.** "Staged but
unverified" is not an outcome it offers. It is also idempotent — re-running prints
`already staged and verified` and does not re-copy 256 MB.

### What landed, and why the tokenizer changed its name

```
C:\dlp\model\model.onnx          the graph (opset 17, IR 8)
C:\dlp\model\model.onnx.json     labels + chunk geometry + model version  ← NOT optional
C:\dlp\model\tokenizer.json      WordPiece vocabulary (from backbone\tokenizer.json)
C:\dlp\runtime\onnxruntime.dll   ONNX Runtime (optional; see §1.1)
```

The **sidecar** is not optional. The agent derives its path from the model path
(`model.onnx` → `model.onnx.json`) and reads the 29-label space, the chunk geometry, the
character limit and the model version **out of it**, so a graph can never be read with
another model's labels. A model staged without its sidecar loads nothing.

The **tokenizer is renamed** from `backbone\tokenizer.json` to `model\tokenizer.json` so
an endpoint carries one model directory instead of the repository's two.

### Verifying by hand (if you staged the files some other way)

```powershell
Get-FileHash C:\dlp\model\model.onnx      -Algorithm SHA256 | Format-List Hash
# EXPECT 6BB36568C1E782569C3C64A8F0DD41C8E463C76D64917E6DBF8B7ED5339E29EF
Get-FileHash C:\dlp\model\tokenizer.json  -Algorithm SHA256 | Format-List Hash
# EXPECT CE64FCE797C24F68DF90B40A3F74F579B336A493DB14BD583FD520EA0D8C9A98
Get-FileHash C:\dlp\model\model.onnx.json -Algorithm SHA256 | Format-List Hash
# EXPECT 4C37BFA10FEEC6A1CCD0878E95B4FE2A1B04F8C6BFE29818A8AB061D0DFCD4A2
(Get-Item C:\dlp\model\model.onnx).Length   # EXPECT 268023580
```

---

## 3. Agent config — the `[ml]` block

Edit `C:\ProgramData\DLPAgent\agent.toml` (or whatever `DLP_AGENT_CONFIG` points at).
The whole section is optional and every field defaults, so add only what differs from the
default (`model\` beside `dlp-agent.exe`):

```toml
server_url   = "https://desktop-k8e7f5d:8443"
ca_cert_path = "C:\\dlp\\ca-cert.pem"
state_dir    = "C:\\dlp\\state"

[ml]
enabled        = true                              # LOCAL kill switch only
model_path     = "C:\\dlp\\model\\model.onnx"      # sidecar is read from <this>.json
tokenizer_path = "C:\\dlp\\model\\tokenizer.json"
intra_threads  = 1                                 # keep the user's PC responsive
# max_chars  = 200000   # reference pipeline's text.max_chars — a compatibility constant
# max_chunks = 0        # 0 = unlimited = reference-faithful. Non-zero classifies a PREFIX.
```

**Split of authority — worth understanding before the console step.** This section says
only *where the model lives* and *what one inference may cost on this machine*. It cannot
say what is sensitive. `enabled = true` here with an inert console policy still classifies
nothing, and an endpoint can never widen its own detection by editing `agent.toml`.
**Which business functions are sensitive, and at what confidence, is console policy
delivered over mTLS.**

---

## 4. Console — turn the classifier on

Log in to the console (`http://<server>:3001`) as a **`policy_author`** — that is the role
holding `ml_policy:write`. A `sysadmin` or `auditor` can open the page (`ml_policy:read`)
but the Save button will be inert for them; that is the two-gate model working, not a bug.

Open **Classification (ML)** in the sidebar (`/ml-policy`).

1. **Turn it on.** Toggle *"Classify documents with the on-device model"*. Everything
   below stays inert until this is on.
2. **Mark the sensitive classes.** The 29 classes are grouped for display only —
   **general** (13), **education** (3), **defence** (13). The grouping is cosmetic; the
   ids and their indices are frozen.
   - Tick **FIN — Finance** in *general*.
   - Tick **NUC — Nuclear & Strategic Systems** in *defence*.
   - The counter under the list should read **2 of 29 classes marked sensitive**.
   - Each ticked class has a threshold box beside it. **Leave FIN's empty** — empty means
     "inherit the global threshold". **Type `0.85` in NUC's** — a per-class override, so
     the class you care most about demands more confidence than the rest. (This is the
     shape the policy carries on the wire: `{"id":"FIN","minConfidence":null}`,
     `{"id":"NUC","minConfidence":0.85}`.)
3. **Set the global threshold.** *Confidence threshold* → `0.70` is the shipped default
   and a sane starting point. Read the caution the page prints: this is a **softmax spread
   across 29 classes**, not a two-way yes/no, so a *correct* prediction routinely sits at
   0.4–0.8. See §9.
4. **Choose the action.**
   - **Audit** — the model's opinion is recorded on incidents and nothing is blocked. Run
     a site here for a week and look at what it flags **before** you switch to Block.
   - **Block** — an ML-only hit blocks on egress channels exactly like a fingerprint hit.
   For the demo, start on **Audit** for cases (a)–(c), then flip to **Block** for the live
   channels in §7.
5. **Fail-block.** *"Block when the model cannot classify a file"* — leave **on** for a
   defence posture: a document we could not classify should not leave the machine. It only
   acts on **egress** channels and only while the action is Block; the synchronous kernel
   read path never fail-blocks on the model (§9).
6. **Save policy.** Expect *"Saved. Endpoints apply it on next check-in."*

Everything on that page commits in **one transaction with a hash-chained audit entry** —
the policy row, its label set and the audit record together. The audit line records the
label *count*, not the document content of anything.

---

## 5. Push it to the endpoint and confirm it landed

The endpoint pulls `GET /agent/ml-policy` over mTLS on check-in and again on every resync
(the interval is `checkin_interval_seconds`, default **300 s**, floored at 30 s for the
resync worker). To stop waiting, restart the service:

```powershell
sc stop DLPAgent ; sc start DLPAgent        # elevated
```

Then watch the agent log:

```powershell
Get-Content C:\ProgramData\DLPAgent\logs\dlp-agent.log -Tail 40 -Wait
```

**The line to look for:**

```
synced ml policy from server   enabled=true labels=2 action="audit" model_version="V6.2.01"
```

`labels=2` is the confirmation that FIN and NUC arrived. The line carries a **count**, not
the selected ids — deliberate: policy is admin configuration, a count is all an operator
needs, and it keeps the log free of anything resembling classification output.

**The cache file** — the fail-secure half:

```powershell
Get-Content C:\dlp\state\ml-policy.json
```

That is the last-synced policy persisted to disk. If the server is unreachable, the agent
logs

```
ml policy sync failed — using last-persisted policy (offline, fail secure)
```

and **keeps applying this file**. It never drops to "off" because the network went away.
An agent that has *never* synced falls back to the inert default (disabled, no labels),
which is exactly the pre-ML behaviour.

> **Where this happens in the agent.** One function, `activate_ml` in
> `dlp-agent/src/main.rs`, publishes the policy **and** loads the ONNX graph — always
> together. It is called from five places: `cmd_run_endpoint`'s startup and its resync
> worker (both syncing from the server, beside `sync_read_deny_policy` /
> `sync_clipboard_policy`), `cmd_usb_guard` (which syncs too), and `cmd_clipboard_agent` /
> `cmd_browser_host`, which read the cache `run_endpoint` just wrote rather than adding an
> mTLS round trip to every session launch. `dlp-agent.exe once` performs the *check-in*
> but does not pull policy.
>
> **Why together:** a published policy with no loaded graph is not a dormant feature. Every
> classify then returns `unavailable`, and `failBlock` (default `true`) denies **every** USB
> write, clipboard copy and browser upload on the machine. That is correct fail-secure
> behaviour for a model that genuinely broke, and an outage when it happens because nobody
> loaded the graph. `tests/ml_golden.rs ::
> policy_without_engine_is_unavailable_and_with_engine_is_ok` pins both halves so they
> cannot be split again.

---

## 6. THE DEMO — four cases at the command line

Two commands do all of it:

- **`dlp-agent.exe classify`** — the model **alone**. No bundle, no fingerprinting, no
  policy. The CLI equivalent of the reference pipeline's `predict.py`: it answers "does the
  model run on this box, and what does it say?" It never says *sensitive* — that is
  `scan`'s job.
- **`dlp-agent.exe scan`** — **both** signals, fused, with the VERDICT banner.

Stage three files on the VM. All three live in the repository's `samples\` directory, so
copy that folder across rather than inventing documents on the day:

| File (`samples\` in the repo, `C:\demo\` on the VM) | What it is | sha256 |
|---|---|---|
| `OperationHimalayanShield_OPORD.pdf` | **registered** — in the compiled index bundle (IDM) | `9ac29e2e…88724e49` |
| `unregistered_reactor.txt` | **not registered** — reads unmistakably as nuclear/strategic material. This is the case the model exists for | `a1eff1fc…3bdcc9e` |
| `lunch_menu.txt` | neither — a canteen menu | `362b474a…8a863e09c` |

> The two `.txt` files are **synthetic**, written for this runbook. They prove the
> *plumbing*, not the model's accuracy: the reactor text is dense with domain vocabulary
> and is close to the easiest possible input. Before trusting a threshold in production,
> run `classify` over a folder of your own real documents whose business function you
> already know.

First, prove the model itself works on this box — before anyone argues about thresholds:

```powershell
cd C:\dlp
.\dlp-agent.exe classify --text "Quarterly budget variance, total expenditure forecast and departmental allocations for the financial year"
```

Prints exactly these five lines (values depend on your text):

```
model:      V6.2.01
label:      FIN — Finance
confidence: 99.81%
chunks:     1
tokens:     24
```

If that works, the model, the tokenizer, the sidecar and ONNX Runtime are all correct on
this machine. Add `--json` for `modelVersion/labelId/labelName/labelIndex/confidence/
chunks/tokens` — the same camelCase vocabulary the verdict's `ml` block uses.

> **Verifying a build, not an endpoint.** `cargo test` **can be fully green with every
> ONNX test skipped** — the golden tests opt out when the 256 MB model or the runtime is
> absent, a skip prints `ok`, and the `SKIPPING` line is hidden unless you pass
> `--nocapture`. A build whose inference path was never executed looks exactly like one
> that passed. So before shipping, run the suite in strict mode, where a missing model or
> runtime is a hard failure:
>
> ```powershell
> $env:DLP_ML_STRICT = "1"
> cargo test --test ml_golden --test ml_chunker
> ```
>
> The ONNX tests take ~60 s when they genuinely run and ~15 s when they skip; the timing
> alone tells you which happened.

### (a) A registered protected document — fingerprint fires, the model may or may not

```powershell
.\dlp-agent.exe scan --file C:\demo\OperationHimalayanShield_OPORD.pdf `
                     --bundle C:\dlp\state\index.dlpx
```

Expect the fingerprint half to name the document and the fused banner to say SENSITIVE.
The scan prints, in order: `file` / `sha256` / `bundle` / `extraction`, then the IDM and
EDM lines, then the `classification:` block, then:

```
============================================================
  VERDICT: SENSITIVE   (signal: idm, severity: high)
============================================================
```

If the model *also* recognises it as, say, OPS or INT and that class is marked sensitive,
the signal reads `idm+ml` and the severity rises to **critical** — both detectors agreeing
independently. If the model's class is *not* marked (an OPORD is most likely OPS, which
you did not tick), the classification block prints
`sensitive: no (label not selected, or under its threshold)` and the verdict is still
SENSITIVE on the fingerprint alone. **That is correct and worth pointing out: the model
never downgrades a fingerprint hit.**

### (b) An UNREGISTERED document whose class is marked sensitive — the whole point

```powershell
.\dlp-agent.exe scan --file C:\demo\unregistered_reactor.txt `
                     --bundle C:\dlp\state\index.dlpx
```

Nobody registered this file. Fingerprinting has nothing to match, so `idm: no matches` and
`edm: no row hits`. Then:

```
classification:
  label:      FIN — Finance
  confidence: 96.40%
  chunks:     3 (1487 tokens)
  model:      V6.2.01
  sensitive:  yes (label selected in policy, at or over its threshold)

============================================================
  VERDICT: SENSITIVE   (signal: ml, severity: medium)
============================================================
```

**`signal: ml` with an empty fingerprint half is the demo.** Before the classifier this
file was invisible to the product. Severity `medium` is honest: one signal, and a
statistical one.

On a machine that never enrolled and therefore has no synced policy, the same case can be
forced for a demo without a console:

```powershell
.\dlp-agent.exe scan --file C:\demo\unregistered_reactor.txt --ml-labels FIN,NUC --ml-min-confidence 0.70
```

Those flags override the console policy **for that one invocation only** — nothing is
persisted, no endpoint setting changes. On an enrolled endpoint the console is the
authority. (Omitting `--bundle` is also legitimate: the fingerprint half then prints
`fingerprinting: no bundle loaded` — *unmeasured*, not "clean" — and the model runs alone.
That is how a site demonstrates the second signal before registering anything.)

### (c) Neither — not sensitive

```powershell
.\dlp-agent.exe scan --file C:\demo\lunch_menu.txt --bundle C:\dlp\state\index.dlpx
```

```
idm:        no matches
edm:        no row hits
classification:
  label:      OOD — Other / Unknown
  confidence: 71.30%
  chunks:     1 (96 tokens)
  model:      V6.2.01
  sensitive:  no (label not selected, or under its threshold)

------------------------------------------------------------
  VERDICT: not sensitive
------------------------------------------------------------
```

The model still returns a label — it always returns *something*, that is what a 29-way
softmax does. `sensitive: no` because OOD is not ticked. Show this one: it is the false
positive rate people actually care about.

### (d) The model removed — `unavailable`, and what fail-block then does

```powershell
Rename-Item C:\dlp\model\model.onnx model.onnx.bak
.\dlp-agent.exe scan --file C:\demo\unregistered_reactor.txt --bundle C:\dlp\state\index.dlpx
```

The `classify` command refuses outright with a message naming every path it expected —
that is a configuration mistake an operator can fix, so it is not silently swallowed:

```
the ML classifier is not installed on this machine — missing:
  C:\dlp\model\model.onnx
  ...
```

`scan` does **not** fail. It writes the same explanatory load error to **stderr**, then
prints the fingerprint half normally and, in the classification block, a non-ok status:

```
classification:
  unavailable (model_not_loaded) — model V6.2.01
```

(The one exception: if you also passed `--ml-labels` / `--ml-min-confidence`, you asked
for the model *explicitly*, so `scan` returns the error rather than degrading quietly.)

**A non-ok status is never a clean bill of health.** It says the model owed an answer and
did not give one, and that is exactly what `failBlock` weighs:

| Where | `failBlock: true`, action Block | `failBlock: false` |
|---|---|---|
| USB / removable write, clipboard copy, browser upload (**egress**) | **BLOCKED** — a document we could not classify does not leave the machine | allowed; the fingerprint signal still applies on its own |
| Kernel read-deny (`DLP_REASON_READ`) | **never fail-blocks on the model** — see §9 | same |

Put the file back afterwards:

```powershell
Rename-Item C:\dlp\model\model.onnx.bak model.onnx
```

Other statuses you may see instead of `ok`: `skipped` / `read_path_skip` (the kernel read
path, by design), `policy_off` (classifier inert), `empty` / `no_text` (nothing was
extracted), `load_failed`.

---

## 7. The live channels — make it happen for real

Switch the console policy action to **Block** and save, then restart the agent service so
the endpoint has it (§5). Use `unregistered_reactor.txt` — the **unregistered** file — for
all three, because that is the one only the model can see.

### USB / removable media

With `usb-guard` running and the driver loaded (`USB-DEMO-RUNBOOK.md` §3–4), copy the file
to the stick:

```powershell
Copy-Item C:\demo\unregistered_reactor.txt E:\
```

**EXPECT:** blocked — the file is removed on handle close, the guard logs a block, and a
"Blocked by DLP" toast appears. In the console **Incidents**: channel **`usb-kguard`**,
action `blocked`, and the incident carries the classifier chip — label `FIN`, its
confidence, `signal: ml`.

### Clipboard

```powershell
.\dlp-agent.exe clipboard-monitor        # or the session helper under run-endpoint
```

Open the document, select all, copy. **EXPECT:** the paste is denied and an incident lands
on channel **`clipboard`** with the same `ml` signal. (Clipboard needs the clipboard policy
in enforce — see the clipboard runbook; the ML signal rides the same verdict.)

### Browser upload

With `browser-host` running and the extension installed, attach the file to any upload
form. **EXPECT:** the upload is blocked and an incident lands on channel **`web-upload`**.

### Where to look in the console

**Incidents** (log in as an `incident_reviewer`; a `sysadmin` deliberately cannot read
evidence). Each incident now shows **one chip per signal**, because detection is no longer
one thing:

- a **fingerprint** chip — the matched document/collection, containment and coverage;
- a **classifier** chip — the label id and name, the confidence, and the model version
  (`V6.2.01`), so an incident can be traced to the exact weights that produced it.

An incident with only the classifier chip is case (b) in production. An incident with both
is `severity: critical`.

---

## 8. Troubleshooting

**"the ML classifier is not installed on this machine — missing: …"**
The three artifacts are not all where `[ml]` says. The message names every path it looked
at. Re-run `stage-ml-model.ps1` and check `model_path`/`tokenizer_path` in `agent.toml`.
Remember the sidecar is derived (`model.onnx` → `model.onnx.json`) and is **not**
configurable — if you renamed the graph, the sidecar has to follow.

**Status `unavailable` even though the files are present → ONNX Runtime.**
The most common cause by far. Confirm one of the three resolution paths in §1.1 actually
has the DLL, most simply:

```powershell
Test-Path C:\dlp\runtime\onnxruntime.dll
$env:ORT_DYLIB_PATH
```

Note `<ml root>` is the **parent of the model directory** — with `C:\dlp\model\model.onnx`
the shipped location is `C:\dlp\runtime\onnxruntime.dll`, not `C:\dlp\model\runtime\`. It
never crashes the agent: `ort` is loaded through a resolved path precisely so a missing
library is a `Result`, not a panic.

**`graph_optimization_level is not valid`, or another odd session-builder error.**
This is not a corrupt model — it means a *different* `onnxruntime.dll` was loaded. With
nothing at the shipped location and no `ORT_DYLIB_PATH`, resolution falls through to the
bare file name and the OS loader binds whatever `onnxruntime.dll` it finds first on the
machine (another application's copy, an older API). Observed on a developer box during
integration. **Always stage the DLL at `<ml root>\runtime\`** so resolution never reaches
the loader path; that is the whole reason the shipped location is first in the order.

**Tokenizer missing or mismatched.**
A wrong `tokenizer.json` does not error — it produces *nonsense labels*, confidently. This
is why the staging script pins its hash. If labels look random, hash the tokenizer
(§2) before you suspect anything else.

**Policy enabled but no classes selected.**
The classifier is **inert**: it runs nothing and contributes nothing, by design. The
console shows `0 of 29 classes marked sensitive`, and `ml.sensitive` can never be true
because no label is in the policy set. Tick at least one class.

**Everything comes back OOD (Other / Unknown).**
OOD is the model's honest "I don't recognise this business function" and it is a real
class, not an error. Usual causes: the text extraction failed or produced junk (check the
`extraction:` line on the scan output — `unreadable` means the model never saw text), the
document is boilerplate/forms/tables with little prose, or the document genuinely isn't one
of the 28 other functions. Run `classify --text "<a paragraph you paste yourself>"` to
separate "the model is broken" from "extraction is broken".

**Confidence always below the threshold.**
Expected on a first deployment at 0.70. The confidence is a **softmax over 29 classes** —
a correct prediction sitting at 0.45 is normal when two related classes split the mass
(FIN vs ACQ, INT vs CYB). Run a week in **Audit**, collect the confidences the site
actually produces on its own documents, then set the global threshold and the per-class
overrides from that data. Tuning per site is expected, not a defect.

**Slow scans on large files.**
Inference cost scales with chunk count: 510 content tokens per chunk, ~200,000 characters
maximum, so a long document is dozens of chunks in one forward pass. `intra_threads = 1` is
deliberate — the agent must not peg an employee's cores — so a big PDF takes seconds, not
milliseconds. Options, in order of preference: leave it (egress channels classify on an
async budget), or set `[ml] max_chunks` to a non-zero cap. **Understand what the cap
does:** the document is then classified from a *prefix*, which diverges from the reference
pipeline. A capped result carries `chunksTruncated` — the chunk count the document really
had — beside `chunks`, the number actually fed to the graph, so a truncated read is never
presented as a full-document verdict. The field is absent when nothing was capped, which is
the default. Do not enable it quietly.

`[ml] max_chars` is a different thing and is **not** a tuning knob: it must match the
`max_chars` the model's sidecar declares (200,000) or the agent refuses to load the
classifier. That bound is applied before a single token exists, so a lower value would
shorten every document before the model saw it and nothing in the output would show it.
Leave it at `0` to accept whatever the model declares.

**`ml` block absent from the verdict entirely.**
`ml` is optional on the wire (`skip_serializing_if = "Option::is_none"`), so an older
consumer and the frozen golden vectors are unaffected. Absent means the classifier was
never invoked: `[ml] enabled = false`, `--no-ml` on the command line, or a channel that
does not classify.

---

## 9. Limitations — read this before you promise anything

1. **The kernel read-deny path does not run the model.** `DLP_REASON_READ` is a
   *synchronous kernel up-call*: a thread is blocked in the file system waiting for our
   answer, and a hundred-millisecond forward pass there is a hung desktop. That path stays
   **fingerprint-only** and reports `status: "skipped"`, `reason: "read_path_skip"`. It
   also **never fail-blocks on the model** — an unavailable classifier must not turn into
   denied reads across the machine. The model runs on write scans, USB, clipboard and
   browser upload, where there is an async budget. (Same precedent as the OCR policy in
   `src/ocrpolicy.rs`.)
   **Still true, and now only half the story:** the read path never *runs* the model, but
   it does **look up** what an off-path producer already learned about the same bytes — a
   hash plus a `HashMap` read, microseconds. See §10 and `ML-PIPELINE-RUNBOOK.md`. It
   still never fail-blocks on the model.
2. **The model reads extracted TEXT, not documents.** It never opens a file format and
   never runs OCR. A scanned PDF, a screenshot or a photographed page produces no text, so
   the classifier reports `empty` / `no_text` and contributes nothing — **unless the OCR
   policy is on**, in which case OCR supplies the text and the classifier scores it. If
   image-borne documents matter at your site, the OCR policy is a prerequisite, not an
   optional extra.
3. **Confidence is spread over 29 classes, so thresholds need tuning per site.** 0.70 is a
   default, not a recommendation. Related classes split probability mass; a *correct*
   prediction can sit under any fixed bar. Run in Audit, measure, then set the global
   threshold and per-class overrides. A site that ships the default and never looks will
   either miss documents or drown in them.
4. **The model states business FUNCTION, not classification LEVEL.** `NUC` means "this
   reads like a nuclear/strategic-systems document". It does **not** mean SECRET, and
   nothing in the taxonomy encodes a marking. The mapping from function to sensitivity is
   the *admin's* decision, made once at setup on the Classification (ML) page — that is
   why the page exists and why the model ships with nothing pre-ticked.
5. **It is statistical, and it names nothing.** The classifier cannot tell you *which*
   document leaked, only what kind it was. That is why the fused verdict is OR and why
   fingerprinting is not going anywhere: registered material still deserves the precise,
   forensic answer. `severity: medium` on an ML-only hit encodes exactly this.
6. **The usual endpoint limits still stand.** Screen-view and a phone camera (the analog
   hole), a kernel-privileged adversary, and laundering through an allowlisted application
   are out of scope for any of this. The classifier widens *coverage*; it does not change
   the threat model.

---

## 10. Next: covering the files nobody is exfiltrating yet

Everything above proves the model works on a machine and answers about a document you hand
it. It leaves one gap, and it is the gap the customer cares about: **a document created on
`C:\` this morning has never met the model**, so when RustDesk, AnyDesk or an RDP session
reads it, the kernel read path adjudicates it on fingerprints alone — and fingerprinting
cannot see a document nobody registered.

That gap is closed by the **ML coverage pipeline**: three triggers (a directory watcher at
creation, a throttled discovery walker at rest, and an on-demand background classify on a
read-path cache miss) feeding one content-keyed verdict cache, which the kernel read path
consults with a hash lookup instead of an inference.

**→ `ML-PIPELINE-RUNBOOK.md`** is the runbook for turning that on across a fleet. Read it
before you touch `denyUnclassified` in the console — it is the one control in this feature
that can deny half an estate on Monday morning, and the rollout order (deploy → sweep →
**verify** → enable) is not optional. It covers:

- what each trigger costs and what each guarantees;
- why the read path may never run the model (the 500 ms kernel budget, the eight-timeout
  IPC circuit breaker, the single-threaded kguard message loop);
- the six-step rollout with a verification gate at each step, built around
  `dlp-agent.exe ml-status`;
- what an end user sees when a read is denied for being unclassified, and what support
  should tell them;
- tuning (scopes, walker rate, filters, queue capacity, cache cap), troubleshooting
  (a cache that never hits — the 4 MiB prefix rule is the non-obvious one — HMAC failures,
  sweeps that never finish, watcher overflow, a broken model with the flag armed), and an
  honest limitations section.

The quick local check, on any endpoint:

```powershell
.\dlp-agent.exe ml-status        # closes with one sentence: is this box ready for denyUnclassified?
```
