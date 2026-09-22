# ML Coverage Pipeline — Production Rollout Runbook

**Goal:** turn on at-creation, at-rest and on-demand document classification across a
fleet — and get to `denyUnclassified` — **without denying half the estate on Monday
morning.**

`ML-CLASSIFICATION-RUNBOOK.md` gets the model onto a machine and proves it answers. This
runbook is what comes after: the model now has to answer about files **nobody is
exfiltrating yet**, so that when somebody does, the answer is already known. That is a
fleet operation with a sequencing problem, and the sequencing is the whole document.

> **Read this before you touch the console switch.** There is exactly one dangerous
> control in this feature — `denyUnclassified` — and it is dangerous in a specific,
> predictable way: enabled before the discovery sweep has finished, it denies the **first
> read of every legacy document on every endpoint**. Everything else here is coverage
> plumbing that changes no decision.

---

## 0. The hole this closes

Before this work, a document created on `C:\` never met the model. The write/quarantine
path deliberately skips fixed volumes — copying a sensitive file `C:` → `C:` is not
exfiltration and must never be quarantined — so the model only ever ran on a file that was
already **on its way out** (USB write, clipboard, browser upload, an explicit `scan`).

The kernel read path never ran it at all. So when RustDesk, AnyDesk or an RDP session
reached for a document, the read was adjudicated on **fingerprints alone** — and
fingerprinting cannot see a document nobody registered. A file written this morning was
invisible to the product until somebody tried to copy it to a USB stick.

Three triggers now feed **one content-keyed cache**, and the kernel read path enforces
against that cache:

| Trigger | Module | What it costs | What it guarantees |
|---|---|---|---|
| **At creation** — a file is classified seconds after the writer closes it | `src/ml/watch.rs` (`ReadDirectoryChangesW`, one thread per scope, 2 s settle) | Cheapest of the three: it only ever looks at files somebody actually touched. One forward pass per finished document. | Everything written while the agent is running is known **before** anyone reads it. This is what keeps trigger (3) the exception rather than the rule. |
| **At rest** — a throttled sweep backfills what predates the agent | `src/ml/walk.rs` (120 files/min default, resumable, checkpointed) | Hours of low-priority background I/O, once, then a re-sweep every 6 h. Throttled three ways (rate budget, queue backpressure, slow-disk penalty). | Files that predate the agent, arrived while the service was stopped, or were lost to a notification-buffer overflow. **This is the component that earns the right to enable `denyUnclassified`** — its completion record is the coverage evidence. |
| **On demand** — a read-path cache MISS enqueues the bytes the driver already handed us | `src/ml/queue.rs` (bounded, one worker, dedup by key) | One background classification per unseen file. With `denyUnclassified` **on**, also one denied read and a user-visible retry. | The guarantee holds whether or not (1) and (2) covered the file. Self-healing: the next read of the same content is a HashMap hit. |

Plus a fourth, free one: the kguard **WRITE** path classifies inline exactly as it always
did, and now **deposits its result into the same cache** (`queue::deposit`). A file
scanned on its way to a USB stick is already known when RustDesk later reads it.

**Nothing in this pipeline raises an incident.** Classifying a file is not a detection —
only enforcement is. Per-file incidents from a walker would flood the console on day one.
Coverage is reported as counters (`ml-status`, and on the check-in heartbeat), never as an
incident feed.

---

## 1. Why the read path cannot just run the model

**If you are reading this in a year and about to "simplify" the cache away: don't. Here is
the arithmetic.**

`DLP_REASON_READ` is a **synchronous kernel up-call**. `DlpPreRead` →
`DlpExfilClassifyAndCache` reads the file in-kernel, ships up to `DLP_MAX_CONTENT` (4 MiB)
of content to the agent, and **blocks the reading thread** until we reply. Three hard
numbers bound what we may do in that window:

1. **`DLP_REPLY_TIMEOUT_MS = 500`.** The driver waits half a second for a verdict.
2. **`DLP_BREAKER_THRESHOLD = 8`.** Eight consecutive IPC **timeouts** trip a circuit
   breaker and every up-call on the machine short-circuits to `FailMode`. That is not a
   slow endpoint, it is a **fleet-visible outage** on one PC — protection either off or
   everything denied, depending on the deployment's fail mode.
3. **The kguard message loop is single-threaded.** `FilterGetMessage` → decide →
   `FilterReplyMessage`, serially. One slow scan does not delay *that* file — it delays
   **every other scan on the machine**.

A DistilBERT forward pass costs ~10–100 ms typically and **~640 ms at eight chunks** (the
model card's own number). 640 > 500. Running inference on that loop is not "sometimes
slow": it is a timeout, and eight documents in a row is the breaker.

So the read path does the one thing that fits inside microseconds: **SHA-256 the buffer the
driver already gave us, and look it up in a `HashMap`.** The model runs somewhere else,
earlier, off the hot loop. That is the entire justification for `src/ml/cache.rs`,
`watch.rs`, `walk.rs` and `queue.rs` existing at all.

The read path's code says the same thing in one line —
`detect::decide::read_path_ml()` is a **lookup**, never an inference, and
`detect::decide::ml_read_path_skip()` is still there beside it as the definition of the
pre-cache behaviour an inert policy must remain byte-identical to.

### The deny-now / classify-later primitive

On a MISS with `denyUnclassified` **on**, the agent replies `None`
(`DLP_VERDICT_NOVERDICT`). Per `comms.c` and `dlpflt.c` that reply:

- makes `DlpQueryVerdict` return `STATUS_NOT_FOUND`, so the read **fails safe per
  `gDlpData.ExfilReadFailBlock`** (default `1` = deny, completing the read as
  `STATUS_ACCESS_DENIED`);
- **seeds nothing** into the driver's cross-open caches, so the *next* read of the same
  file up-calls again — which is what lets the queued classification make the retry
  authoritative;
- **explicitly does not count toward the IPC circuit breaker.** So even a machine where
  every read is denied for a while cannot trip itself into `FailMode`.

That primitive already existed (it is what the no-bundle startup window uses). This
feature reuses it; **no driver change was made for any of this.** `DLP_MSG_VERSION` stays
at 2, no `.c`/`.h` was touched, nothing was re-signed, no reboot is required.

---

## 2. Prerequisites

Everything in `ML-CLASSIFICATION-RUNBOOK.md` §1–§5 must already be true on the endpoint:

| Requirement | Check |
|---|---|
| Model artifacts staged and **hash-verified** (`model.onnx`, `model.onnx.json`, `tokenizer.json`) | `stage-ml-model.ps1` reports `All SHA-256 verified` |
| **ONNX Runtime** resolvable — the prerequisite people miss | `Test-Path C:\dlp\runtime\onnxruntime.dll` |
| The model actually runs on this box | `.\dlp-agent.exe classify --text "…"` prints a label |
| A console ML policy that is **not inert** — enabled, with at least one class ticked | `.\dlp-agent.exe ml-status` → `classes selected: N` (N ≥ 1) |
| The **service** role is what runs the pipeline | `run-endpoint` / the `DLPAgent` service. `usb-guard` gets the cache and the on-demand worker but **not** the sweepers; per-session helpers get lookups only. |
| A read-deny watch-set (`[kguard] watch_paths`) that describes where the customer's documents actually live | `ml-status` → `scopes: N configured`, and the list beneath it |

**Inert ⇒ nothing at all.** `main.rs::activate_ml` returns before the cache is even opened
when the policy is inert, so an endpoint whose console has selected no label behaves
byte-for-byte like the agent that predates this feature: no cache file, no threads, no disk
traffic (contract F3). That is what makes the agent safe to deploy ahead of the console
change that enables it.

---

## 3. Agent config — the `[ml]` pipeline block

These sit beside the `model_path` / `tokenizer_path` settings the classification runbook
covers. **Every one of them defaults**, and the defaults are the shipping posture; add
only what differs.

```toml
[ml]
enabled              = true      # LOCAL kill switch (beats the console). Restart to change.

# --- the coverage pipeline ---
watch_enabled        = true      # at-creation watcher
walk_enabled         = true      # at-rest discovery walker
walk_files_per_minute = 120      # walker throughput ceiling; 0 = unlimited
walk_interval_hours  = 6         # hours between full re-sweeps
queue_capacity       = 256       # on-demand classify queue depth
cache_max_entries    = 200000    # verdict cache hard cap, LRU beyond it
max_file_bytes       = 67108864  # 64 MiB — skip bigger files (I/O bound, not model bound)
# scopes = ["D:\\Shares"]        # NORMALLY EMPTY — derived from [kguard] watch_paths
```

**Scopes are one list, not two.** `Config::ml_scopes()` derives the trees the watcher
watches and the walker sweeps from the read-deny watch-set (`[kguard] watch_paths`), so
the two cannot drift: anything the driver read-adjudicates is something the pipeline must
have classified. Volume-relative driver paths (`\Users`) become absolute
(`C:\Users`), wildcards are truncated to their fixed prefix, and nested duplicates are
pruned to the outermost. With `watch_paths` empty it falls back to the profile root. Set
`[ml] scopes` **only** to override that on a site whose data lives somewhere the driver's
watch-set does not describe.

**Two things that need a service restart, not a resync:**

- `[ml]` settings themselves — the config is read from disk at process start.
- **The scopes.** `start_ml_sweepers` reads `ml_scopes()` once and binds the threads to it
  for the life of the process. A console change to `watchPaths` therefore reaches the
  sweepers at the next service restart. Stated plainly because the alternative (tearing
  down and rebuilding directory watches mid-sweep) buys very little for a value that
  changes about once per deployment.

Everything the **console** owns — classes, thresholds, action, `failBlock`,
`denyUnclassified` — applies on the next resync with no restart.

---

## 4. THE ROLLOUT

Six steps. **Each has a verification gate; do not skip a gate to save an afternoon.** The
gates exist because step 5 is irreversible-feeling to a user even though it is instantly
reversible to you.

### Step 1 — Deploy the agent with ML on and `denyUnclassified` OFF

Console → **Classification (ML)** (`/ml-policy`), as a `policy_author`:

- Classification **on**, at least one class ticked, threshold set (see the classification
  runbook §4 and §9 — 0.70 is a default, not a recommendation).
- Action: **Audit** for the first week. You want to see what the model flags before it
  blocks anything.
- **`denyUnclassified`: OFF.** It ships off, the console shows it off, and the toggle
  reads *"Off — unclassified files fall back to fingerprints only (recommended)"*.

**What this changes on the endpoint: nothing that blocks.** With the flag off, a read-path
cache miss behaves **exactly as it did before this feature existed** — the fingerprint
half decides, and the verdict's `ml` block carries
`status: "skipped"`, `reason: "not_classified"`, meaning *"we looked, and nobody has
classified these bytes"*. That is a coverage gap a reviewer can act on, not a denial. No
new blocks appear anywhere on day one. (Contract P2, and `tests/ml_readpath.rs` pins it.)

**GATE:** roll to a pilot ring first — a dozen machines that represent your estate's worst
case (the biggest profiles, the slowest disks, the file-server-shaped endpoints). Do not
skip the ring because "it changes nothing"; the point of the ring is step 3's duration
estimate.

---

### Step 2 — Confirm the watcher and the walker are actually running

```powershell
Get-Content C:\ProgramData\DLPAgent\logs\dlp-agent.log -Tail 200 | Select-String "ML |ml watcher|ml walker|ml classify|verdict cache"
```

**The lines that say it started**, in the order they appear at service start:

```
ML classifier loaded — document classification is live on this endpoint   model_version="V6.2.01"
ML verdict cache opened                       entries=0 max_entries=200000
ml classify queue started                     capacity=256
ML coverage pipeline starting                 scopes=1 watch=true walk=true
ml watcher: watching a scope for at-creation classification   settle_ms=2000
ml walker: starting at-rest sweep             sweep=1 scopes=1
```

`ML coverage pipeline starting` logs the scope **count**, never the paths — house rule.
The paths are in `ml-status`, which is a local operator command.

**Lines that mean it did NOT start** — each one is a stop-and-fix:

| Line | Meaning |
|---|---|
| `ML pipeline: no scopes to cover — the watcher and walker will not start` | `ml_scopes()` came back empty. Fix `[kguard] watch_paths` or set `[ml] scopes`. |
| `ML pipeline: no verdict cache published — sweepers not started` | The cache failed to open. The read path stays fingerprint-only; see the preceding warning for why. |
| `could not open the ML verdict cache — the read path stays fingerprint-only` | State-directory permissions, or a full disk. Not fatal, but coverage will never grow. |
| `ML policy is live but the classifier could not be loaded — classification reports \`unavailable\` and egress paths weigh failBlock` | Model artifacts or ONNX Runtime. **Egress channels are now fail-blocking**; fix it before anyone notices. |
| `ML pipeline: a scope covers an entire volume — expect heavy notification churn; set [ml] scopes to narrow it` | Almost always a `watch_paths = ["\\"]` that was meant to be `"\\Users"`. See the read-deny `\` scope note. |

Then confirm from the endpoint's own report:

```powershell
.\dlp-agent.exe ml-status
```

`discovery` must read `watcher: enabled` and `walker: enabled (120 files/min)` with a
non-zero scope count.

**GATE:** every pilot machine shows the six start lines and a non-zero scope count.

---

### Step 3 — Wait for the discovery sweep to complete

The walker starts sweeping **immediately** at service start (and resumes from its
checkpoint after a reboot — a sweep of a laptop takes hours and must survive one).

**The line an operator greps for.** It is emitted once, when a **FULL** sweep of every
configured scope finishes:

```
ml walker: FULL at-rest sweep complete   sweep=1 files=61432 already_known=0 enqueued=58110 skipped=214905 errors=17 duration_secs=31007
```

Related lines that are **not** that line, and do not establish coverage:

- `ml walker: scope re-sweep finished` — a targeted re-sweep after a notification overflow.
  Deliberately does **not** renew the estate-wide claim: re-walking one tree does not
  establish coverage of the estate.
- `ml walker: resumed at-rest sweep from checkpoint` — a reboot; the sweep continues.
- `ml walker: model version changed — restarting the sweep` / `scope configuration changed
  — restarting the sweep` — the previous progress is void, and rightly so.

**How long to expect.** The headline throttle is `walk_files_per_minute`, default **120**
(two per second), and the walker throttles itself *further* when the disk is busy or the
classify queue is deep. So:

| Candidate files in scope | ≈ elapsed **uptime** at 120/min |
|---|---|
| 10 000 | ~1.5 hours |
| 60 000 | ~8 hours (one working day) |
| 100 000 | ~14 hours (one overnight) |
| 250 000 | ~35 hours (two nights) |

Two corrections to that table, both in the same direction:

- **"Candidates" are not "files".** `src/ml/filter.rs` excludes machinery before the
  budget is charged — `node_modules`, `target`, `build`, `dist`, `obj`, `__pycache__`,
  `.git`, `$Recycle.Bin`, `System Volume Information`, temp/cache trees, the agent's own
  state directory and model directory — and only classifies extensions the text extractor
  can actually read. On a developer's machine `skipped` routinely dwarfs `files` by an
  order of magnitude, and skipped entries cost a `stat`, not a read.
- **It is uptime, not wall-clock.** A laptop that is shut at 17:00 resumes on Monday.

Ask the endpoint rather than the table:

```powershell
.\dlp-agent.exe ml-status
```

```
discovery (at-rest walker):
  watcher:        enabled
  walker:         enabled (120 files/min)
  scopes:         1 configured
                  C:\Users
  last full sweep: 2026-09-08 03:41:12Z (8h ago) — 61432 files covered, model V6.2.01
  in progress:    no
```

`last full sweep: NEVER` with `in progress: yes — sweep #1, 12043 dirs listed, 24880 files
looked at so far` is a sweep still running. That is the normal state of step 3.

**GATE:** every machine in the ring reports a completed full sweep **under the model
version the endpoint is running now**. `ml-status` checks that for you — see step 4.

---

### Step 4 — Verify coverage, and read the counters for errors and drops

`ml-status` closes with **one sentence that answers the actual question.** It is ordered by
what would bite first, so it tells you the one thing blocking you rather than a list. Only
one phrasing is a yes:

```
coverage: a full sweep completed 8h ago under model V6.2.01, covering 61432 files —
this endpoint is ready for denyUnclassified. Verify the rest of the fleet before enabling
it centrally.
```

Every other closing line is a **no**, and says why:

| Closing line begins | What to fix |
|---|---|
| `[ml] enabled = false — the local kill switch is on` | The endpoint classifies and caches **nothing**. `denyUnclassified` would deny every read of every file here. |
| `the ML policy is inert (off, or no class selected)` | Nothing to enable yet. Tick a class. |
| `the classifier was not loaded (--no-load)` | Re-run without `--no-load`; this run cannot answer. |
| `the classifier is NOT LOADED on this endpoint` | Model artifacts / ONNX Runtime. Coverage cannot grow here. |
| `the at-rest walker is disabled ([ml] walk_enabled = false)` | Nothing will ever backfill legacy files. |
| `discovery has NOT completed on this endpoint` | Wait (step 3). |
| `the last full sweep completed under model X but this endpoint runs Y` | **Coverage under a superseded model is not coverage** — every entry that sweep wrote reads as stale, i.e. as a miss, i.e. as a denial. Wait for a sweep under Y. |

For fleets, `--json` is the machine-readable form of the same report — gate a rollout on
`readyForDenyUnclassified: true` across the ring:

```powershell
.\dlp-agent.exe ml-status --json | ConvertFrom-Json | Select-Object -ExpandProperty readyForDenyUnclassified
```

(`--json` sends its own log lines to **stderr** precisely so the JSON document is
parseable; every other mode keeps stdout logging byte for byte.)

**Then read the counters.** Two of them are not performance notes:

```
cache (disk-replay):
  entries:        58110
  bytes on disk:  9142208
  hmac failures:  0
  hits/misses/evictions: — (process-lifetime counters; the enforcing process holds them
                         and reports them to the console on check-in)

queue (on-demand classifier):
  depth:          0 / 256
  processed:      58110
  failed:         0
  unextractable:  1204
  dropped:        0
  deduped:        87
  reads denied:   0
```

- **`hmac failures` non-zero is a TAMPER SIGNAL, not a performance note.** The verdict
  cache can cause a file to be **allowed out**; an attacker who can write the state
  directory and relabel NUC content as OOD has an exfiltration path. Every record carries
  HMAC-SHA256 under a per-machine key sealed with DPAPI (machine scope), exactly as
  `src/storage.rs` seals the agent identity. A record that fails verification is
  **discarded** — counted, warned about once, treated as a miss, never trusted. Non-zero
  means somebody or something wrote to that log. Investigate the endpoint before enabling
  anything.
- **`dropped` non-zero means this endpoint is MISSING COVERAGE**, not merely that it is
  busy: a dropped job is content nothing classified. See §6.
- `failed` is the model owing an answer and not giving one (not loaded, load failure,
  inference error) — transient by nature, and deliberately retried rather than remembered.
  A persistently climbing `failed` means the model is broken on this box.
- `unextractable` is content with nothing to classify — an image, an encrypted archive, a
  binary the extractor refuses. **Not a fault**, but read the limitation in §8.1: those
  files stay permanent misses, and with `denyUnclassified` on they stay **denied**.

The **hit/miss ratio and the queue depth cannot be read from a terminal at all** — they are
process-lifetime counters living in the enforcing service's memory, and a freshly started
CLI printing its own zeroes next to a service that has served millions of lookups would be
a lie. They ride the check-in heartbeat instead (`checkin::MlCoverage` → `mlCoverage` on the
check-in body: counts, flags, a model version and unix seconds; **never a path, a file
name, a label distribution or content**).

> **Honest note on the console surface.** The agent *sends* `mlCoverage` on every
> heartbeat, and the payload is additive (a server that has never heard of it ignores it).
> The management server currently reads only `agentVersion` off that body — there is **no
> fleet coverage view in the console yet**. Until there is, step 4 is `ml-status --json`
> collected by your own tooling across the ring. Do not treat the absence of a console
> warning as evidence of coverage.

**GATE:** across the ring — every machine `readyForDenyUnclassified: true`, every machine
`hmacFailures: 0`, every machine `dropped: 0`. Fix the outliers (§6) before step 5.

> **The endpoint holds a veto, and it is why this is survivable.**
> `denyUnclassified` is a single console-wide policy field — there is no per-endpoint
> override in the console. But each agent applies a LOCAL INTERLOCK before honouring
> it: `detect::decide::deny_unclassified()` returns false unless **this** machine has a
> completed discovery sweep (plus a live policy and a running classify worker).
>
> So enabling the flag fleet-wide arms only the machines that are actually covered. A
> laptop that enrolled an hour ago, or one whose sweep is still running, keeps its
> previous behaviour until its own sweep completes — it does not deny the first read of
> every document on it. The interlock re-arms from the persisted completion record on
> service restart, so a reboot does not silently disarm a covered machine.
>
> The interlock can only ever make the feature LESS aggressive than the console asked
> for, never more: a miss on an un-armed endpoint is still the pre-cache
> fingerprint-only answer, never "clean". It is a blast-radius limiter, not a substitute
> for the gate above — verify coverage anyway, because an endpoint that never completes
> a sweep will never enforce, and you want to know that.

---

### Step 5 — Enable `denyUnclassified`

Console → **Classification (ML)** → the red panel at the bottom, as a `policy_author`. The
toggle is behind a two-step acknowledgement modal: it still only takes effect on **Save**,
but the modal is there to make the operator state, before the switch moves, that the
precondition in step 4 is actually met.

**What changes the moment you save:**

- **On each endpoint, at its next check-in** — not instantly, see step 6 for the number.
- A kernel READ whose content is **not in the verdict cache** now gets
  `DLP_VERDICT_NOVERDICT` instead of the fingerprint-only answer. The driver denies it per
  `ExfilReadFailBlock` and **caches nothing**, so the same file re-up-calls on the next
  attempt. The queued classification lands within seconds and the retry succeeds (or
  blocks for a real reason, with a real incident).
- The denial applies **only where the on-demand worker runs** — the service and
  `usb-guard`. `decide::deny_unclassified()` re-checks, on every read, that the policy is
  live **and** that the background worker is running. A denial nothing can ever clear is
  an outage, not a control, so a missing worker disables the deny rather than bricking the
  endpoint.
- **A denial raises no incident** (contract F5). "We do not know yet" is not a detection,
  and since the driver caches nothing, an incident here would be one per *read* — on the
  day you flip this, one per legacy file on every endpoint. The operator signal is the
  **rate**: `queue.readsDenied` plus one aggregated log line at most every 60 seconds:

  ```
  denyUnclassified: reads denied pending classification   denied_total=143 queue_depth=11
  ```

- Nothing else changes. `denyUnclassified` does not touch the sensitivity rule, the
  thresholds, `failBlock`, or any egress channel. It is exclusively about the kernel read
  path's answer to *unknown content*.

**What to watch for the first hour:** `readsDenied` should rise briefly on each endpoint
and then flatten. A `readsDenied` that keeps climbing linearly means the queue is not
keeping up or the cache is not being hit — go to §7, and be ready to do step 6.

---

### Step 6 — Backing out fast

**Turn the toggle off in the console and Save.** That is the whole procedure. There is no
agent-side undo to perform, no restart, no file to edit.

**How long it takes to reach an endpoint:** the resync worker re-pulls every policy on an
interval of `checkin_interval_seconds`, **floored at 30 s**, default **300 s**. So worst
case is **five minutes** from Save to the last endpoint stopping. `activate_ml` runs on
every resync cycle and republishes the flag with the rest of the policy, so this needs no
restart.

To beat the interval on a specific machine:

```powershell
sc stop DLPAgent ; sc start DLPAgent        # elevated — applies the current policy immediately
```

**Escalation ladder, in order of blast radius** — use the smallest one that works:

| Situation | Action | Effect |
|---|---|---|
| Denials on some machines, feature otherwise healthy | `denyUnclassified` **off** in the console | Read-path misses fall back to fingerprints. Coverage keeps growing. ≤ 5 min. |
| The model is misbehaving on egress too | Action → **Audit** in the console | Nothing blocks on the model anywhere; the pipeline keeps classifying. ≤ 5 min. |
| One endpoint must stop classifying entirely | `[ml] enabled = false` in `agent.toml` + `sc stop/start DLPAgent` | Local kill switch — beats the console. The classifier unloads; the agent behaves as it did pre-ML. |
| The whole feature must go | Untick every class (policy goes inert) | **Byte-identical to the pre-feature agent on every path** (F3). No cache, no threads, no disk traffic. |

Note the last row's precision: *inert* is a stronger statement than *off*. It is the
guarantee that makes this feature safe to deploy in the first place.

---

## 5. What the end user sees, and what support tells them

**There is no toast.** A `denyUnclassified` denial is not an enforcement event, so it
raises no incident and pops no "Blocked by DLP" notification. The user sees whatever their
application does with `STATUS_ACCESS_DENIED` on a read:

- Explorer / a copy: **"Access is denied."**
- An RDP or RustDesk/AnyDesk file transfer: the transfer fails, usually with a permissions
  error.
- An application opening the document over one of those sessions: "cannot open file",
  "file in use", or a generic read error — applications are inconsistent here.

**It is transient, per file.** The read that was denied is also the read that queued the
classification. Within seconds — one forward pass, plus whatever is ahead of it in a queue
bounded at 256 — the content is cached, and the *next* attempt is adjudicated normally.
The driver caches nothing on `NOVERDICT` precisely so that retry is possible.

**Support script:**

> *"That file hadn't been checked by the classifier yet, and the policy on this network is
> to hold an unchecked document rather than let it out over a remote session. Wait a few
> seconds and try again — it will normally go through on the second attempt. If it keeps
> failing on the same file, raise a ticket with the file's location and we'll look at it."*

What support should **not** say: that the file is sensitive (nobody has decided that yet —
it is unclassified, not classified-as-bad), or that the user did something wrong.

**When to escalate a user's ticket:** the same file failing repeatedly over minutes is not
the normal case. It means the classification is failing, not merely pending — an image or
an encrypted archive the extractor cannot read (§8.1), a file over `max_file_bytes` that no
producer will touch proactively, or a broken model on that endpoint (§7). Check
`ml-status` on the machine.

---

## 6. Tuning

Every knob below is in `[ml]` in `agent.toml` and needs a **service restart**. The defaults
are deliberately the cheap side of every trade: a producer that never runs costs coverage
(a first read falls back to fingerprints), while a producer that runs too hard costs the
customer their endpoint and gets the agent switched off — which costs *all* protection.

### The walker is too slow (the sweep will not finish in the maintenance window)

```toml
walk_files_per_minute = 600     # 10/s. Raise deliberately, not fleet-wide.
```

- Raise it for a **scripted pre-deployment sweep on a machine nobody is using** — a gold
  image, a bench, a file server out of hours. `0` means **unlimited** and is the right
  setting for exactly that case. **Never ship `0` to a live endpoint.**
- Do not raise it fleet-wide to "finish sooner". The cost of a file is not the forward pass
  alone: it is a 4 MiB read, a text extraction (a PDF or `.docx` is a decompress plus a
  parse), then ~10–100 ms of DistilBERT — on somebody's work PC while they use it.
- The walker throttles itself *on top of* this knob and will ignore your generosity when
  the disk is busy (`slow_read_ms`, default 250 ms → a 4-token penalty) or the classify
  queue is deep (`queue_pause_depth`, default 32 → pause and re-test every 2 s). If a
  raised rate does not produce a faster sweep, one of those is the real limit; the machine
  is telling you it is busy.
- Narrowing **scopes** is usually better than raising the rate. A scope that covers a whole
  volume (`watch_paths = ["\\"]`) sweeps Windows, Program Files and every application's
  data directory to find the customer's documents. `\Users` — or the actual share — is the
  answer, and the agent warns when a scope has no parent.

### The queue is dropping work (`dropped` > 0)

A drop is **lost coverage**. The enqueue never waits (it is called from the kguard message
loop — contract P3), so a full queue discards its **oldest** pending job and counts it:

```
ml classify queue full — dropped the oldest pending classification   dropped=41 capacity=256
```

In order:

1. **Find out who is filling it.** A tight read loop on one file cannot do it — in-flight
   work is deduplicated by key (`deduped`). Broad churn can: a bulk restore, an unpacking
   installer, a sync client rewriting a tree.
2. **Lower `walk_files_per_minute`** if the walker is the producer. The walker already
   pauses at `queue_pause_depth`, so drops from the walker mean a burst outran the check.
3. **Raise `queue_capacity`** only after (1) and (2). Each slot can hold up to 4 MiB of
   content; 256 × 4 MiB is the worst case you are authorising. Doubling it is reasonable on
   a workstation with RAM to spare; 4096 is not.
4. **Tighten the filter** — exclude the tree that is churning via `[ml] scopes`.

### The cache is at its cap (`entries` ≈ `cache_max_entries`, `evictions` climbing)

```toml
cache_max_entries = 500000
```

A record is a 32-byte hash plus a label, an index, a score and a few counts — **no path, no
name, no content** — so 200 000 entries is tens of MB resident. Eviction is LRU and costs
**coverage, never safety**: an evicted entry is a MISS, and a miss can never say "not
sensitive" (F1). With `denyUnclassified` on, though, an evicted entry is a *denial*, so a
site that thrashes the cap will feel it as user-visible retries. Raise the cap on
file-server-shaped endpoints; leave it alone on laptops.

The on-disk log compacts itself when it bloats relative to the live entry count, and a
torn tail record is dropped rather than failing the load. There is **no fsync on the write
path** — losing the tail of a best-effort cache costs one re-classification; an fsync per
file on a walker would cost the endpoint's disk.

### Filters: what gets classified at all

`src/ml/filter.rs` is pure and table-tested (`tests/ml_filter.rs`), and it gates **both**
producers with the same rules:

- **Extensions**: only what `detect::extract` can turn into text — the plain-text family
  plus `docx`, `xlsx`, `pptx`, `pdf`, `zip`. The list is a hand-kept mirror of the
  extractor, and `supported_extensions_match_the_extractor` fails the build if it drifts.
- **Excluded directory names**, wherever they appear: version control and package trees,
  build output, temp/cache, `$Recycle.Bin`, `System Volume Information`.
- **`max_file_bytes`** (default 64 MiB). **Not a model-cost bound** — only the first 4 MiB
  of any file is ever hashed or classified. It bounds *I/O*, and keeps the producers off
  multi-gigabyte artefacts (VM images, mailbox archives, media) that a user may be actively
  streaming.

A skip is a **coverage/cost decision, never a safety one**. It only means no producer will
proactively classify the file; if it is later read on an exfil path, the on-demand trigger
classifies it from the bytes the kernel already handed us, and `denyUnclassified` still
governs the interim. That asymmetry is why the exclusion list can afford to be generous.

### The watcher

`settle_ms` (2 s) and `settle_timeout_ms` (30 s) are module constants, not config. They
exist because `ReadDirectoryChangesW` fires *during* a write, many times per file — Word
writes a temp file, flushes, renames; a download grows for a minute. Reacting to the first
notification classifies half a document, burns a forward pass, and caches a key that will
never be looked up (the finished file has different bytes, so a different key). If a site
genuinely needs different settle behaviour, that is a code change with a test, not a
config edit.

---

## 7. Troubleshooting

### The cache never hits — `entries` climbing, `hits` flat

**This is the non-obvious one, and it has exactly one common cause: the key.**

The cache key is the **lower-case hex SHA-256 of the first `min(file_size, 4 MiB)` bytes**
of the file, and it must be **byte-identical to what the driver hashes and ships**. The
driver reads at most `DLP_MAX_CONTENT` (4 MiB) in-kernel and hands us exactly those bytes
with `DLP_REASON_READ`. The read path can only ever hash *that*. So a producer that hashes
the **whole** file mints a key the read path can never produce — and the failure is
silent and perfect: the cache fills up, reports healthy `entries`, grows a log, evicts
correctly, and **hits zero times, forever**.

That is why `cache::read_prefix_for_hashing` is the single function both off-path
producers use, why `cache::MAX_HASHED_BYTES` is documented as a **contract, not a tuning
knob**, and why nobody should ever "improve" the walker by reading a whole file.

If you are debugging a zero-hit cache, check in this order:

1. **Model version drift.** An entry whose `model_version` differs from the loaded
   engine's is a **MISS by design** (C3). `ml-status` will say so loudly:
   `*** that sweep ran under V6.1 but this endpoint now runs V6.2.01 — every entry it
   wrote is STALE and reads as a miss ***`. A model upgrade invalidates the whole estate's
   coverage; plan a re-sweep with it.
2. **A cache that was never published.** `ML pipeline: no verdict cache published` or
   `could not open the ML verdict cache` in the log. Every lookup misses; every path
   degrades to pre-cache behaviour.
3. **The wrong process.** Per-session helpers (`clipboard-agent`, `browser-host`) get
   lookups only; `usb-guard` gets the cache and the on-demand worker but **not** the
   sweepers. Only the service (`run-endpoint`) runs everything.
4. **Genuinely different bytes.** A file that is rewritten has a different key and a
   different entry. That is the invalidation story working — there is no invalidation
   logic at all, because different bytes are a different key (C3).

`DLP_MAX_CONTENT` and `cache::MAX_HASHED_BYTES` diverging is the same bug in its worst
form. They are the same number by contract; if the driver's constant ever moves, this
cache goes 100% miss silently, and only a test that asserts the equality will catch it.

### `hmac failures` is non-zero

```
ml cache: verdict records failed HMAC verification and were discarded (tamper signal)   failures=12
```

Treat it as a security event on that endpoint, not as corruption. The entries were
discarded and the affected content reads as a miss (safe direction), so nothing was
wrongly allowed out — but somebody or something wrote to the agent's state directory.
Check who can write it, then let the pipeline rebuild the entries.

The adjacent, **benign** line is different and says so:

```
ml cache: HMAC key regenerated — discarding unverifiable verdict log
```

That is the DPAPI-sealed key having become unusable — the machine changed, the profile was
rebuilt, the state directory was restored from another box. A fresh key cannot verify
anything written under the old one, so the log is discarded rather than raising a hundred
tamper warnings. Consequence: **coverage is back to zero on that endpoint.** If
`denyUnclassified` is on, that machine will deny first reads until it re-sweeps — check
`ml-status` and expect `last full sweep: NEVER`.

`ml cache: dropped a torn tail record from the verdict log` is a crash mid-append and needs
no action; it costs one re-classification.

### The sweep never completes

- `in progress: yes` with `candidates` not moving between two `ml-status` runs → the walker
  is throttled, not stuck. Check for `queue_pause_depth` backpressure (`queue depth` at or
  above 32) or a busy disk. Both are the throttles working.
- The sweep **restarts** repeatedly → look for `ml walker: model version changed —
  restarting the sweep` or `scope configuration changed — restarting the sweep`. A model
  or scope that keeps changing (a half-finished staging, a config pushed on a loop) will
  never let a sweep finish.
- `ml walker: checkpoint version mismatch — restarting the sweep` or `unreadable state file
  discarded` → a damaged bookmark costs a restarted sweep, never a failed startup. Once is
  fine; repeatedly means the state directory is unhealthy.
- A machine that is **never on long enough**. A sweep needs hours of *uptime*; a laptop
  that is used for 90 minutes a day takes a week. That is a scheduling fact, not a fault —
  and it is a reason to hold `denyUnclassified` until the slowest ring member is covered.
- `errors` climbing in the completion line → files and directories the agent could not read
  (locked, or an ACL the service does not hold). A handful is normal; thousands means the
  scope includes something the agent has no business walking.

### The watcher overflowed

```
ml watcher: change-notification buffer overflowed — scope marked for at-rest sweep
```

Under heavy churn the kernel's notification buffer overflows and Windows tells us by
completing with zero bytes. **The changes are gone** — there is no way to recover them from
the API. The honest response, and the one the code takes, is to mark that scope for the
walker to re-sweep, because pretending nothing was missed is how a file quietly ends up
unclassified for ever. You will then see:

```
ml walker: re-sweeping scopes whose change notifications overflowed   sweep=7 scopes=1
ml walker: scope re-sweep finished
```

Occasional overflows during a big unpack or restore are expected and self-heal. **Constant**
overflows mean the scope is too broad (a whole volume) or the machine churns constantly —
narrow `[ml] scopes`. Note that a scope re-sweep deliberately does **not** produce a
completion record: re-walking one tree does not establish estate coverage.

### The model is unavailable while `denyUnclassified` is on

Two cases, and they behave very differently. Know which one you have.

**(a) The model never loaded in this process.** `activate_ml` does not start the pipeline
without a graph, so the on-demand worker is not running — and `decide::deny_unclassified()`
requires `ml::queue::running()`. **The deny silently disables itself.** Reads fall back to
fingerprints, exactly as with the flag off. This is deliberate: a denial nothing can ever
clear is an outage, not a control. Egress channels, meanwhile, are fail-blocking per
`failBlock` (default true), so USB/clipboard/upload will be denying — that is the symptom
you will actually hear about.

**(b) The model breaks after the worker started.** The worker keeps running, every job
fails with a transient error, `failed` climbs, **no cache entry is ever written** (F2) —
and because the worker *is* running, `deny_unclassified()` stays true. **Reads keep being
denied and never self-heal.** This is the bad case. Its signature in `ml-status` is
unmistakable:

```
  processed:      0
  failed:         4127
  reads denied:   3980
```

Response: turn `denyUnclassified` off in the console (≤ 5 min), then fix the model. Do not
try to ride it out; every read of every unclassified file on that machine is failing.

Per-file failures are counted, **not logged** — a model that will not load would otherwise
emit one warning per file read on the endpoint. `failed` is the signal.

### Coverage looked fine yesterday and is zero today

Almost always one of: a **model upgrade** (every entry stale — §7.1 case 1), a **state
directory restored or moved** (HMAC key regenerated, log discarded), or **`[ml] enabled =
false`** pushed by a build. `ml-status` names all three in its closing line.

---

## 8. Limitations — read this before you promise anything

These are the honest edges of the guarantee. Everything in §9 of
`ML-CLASSIFICATION-RUNBOOK.md` still applies on top of them (the model states business
*function* not classification *level*; confidence is a 29-way softmax; the classifier names
nothing; the analog hole and a kernel-privileged adversary are out of scope for all of it).

1. **Content the extractor cannot read is a permanent miss.** An image, an encrypted
   archive, a binary, a document that tokenizes to nothing — the model has no answer, and
   per contract F2 **no cache entry is written**. The queue remembers such keys in a small
   bounded `barren` set purely so it stops re-extracting the same bytes, and that set is
   **deliberately not consulted by the read-path decision**: a barren key is still a cache
   MISS. So with `denyUnclassified` on, content the extractor cannot read **stays denied**.
   That is the admin's choice when they enable the flag, and one of the reasons the flag
   ships false. Scanned PDFs and screenshots are the common case here, and the **OCR
   policy is the fix** — with OCR on, the extractor supplies text and these files
   classify normally.
2. **Only the first 4 MiB of a file is ever seen.** The key and the classification both
   cover `min(file_size, 4 MiB)`, because that is all the driver ships. A 40-page report
   whose sensitive annex begins at 6 MiB is classified on its first 4 MiB. The stored entry
   carries `truncated: true` so a report can say so, but the *verdict* is a prefix verdict.
   This is a contract with the kernel, not a tunable: raising it would need a driver change.
3. **Files over `max_file_bytes` (64 MiB) are never proactively classified.** No watcher,
   no walker. They are not a hole — if such a file is read on an exfil path the on-demand
   trigger classifies it from the kernel's prefix — but they are permanently absent from
   the cache until somebody reads them, so with `denyUnclassified` on, the *first* read of
   every large file is denied.
4. **There is a window between creation and settling.** The watcher waits `settle_ms`
   (2 s) of quiet before classifying, and up to `settle_timeout_ms` (30 s) for a file that
   is appended to continuously — then the extraction and forward pass take their own tens
   to hundreds of milliseconds, behind whatever is in the queue. A file read within a
   couple of seconds of being written is a **miss**. With the flag off that read falls
   back to fingerprints; with it on, that read is denied and the retry succeeds.
5. **Formats the extractor does not support are invisible to the producers.**
   `SUPPORTED_EXTENSIONS` mirrors what `detect::extract` can do — the plain-text family
   plus `docx`/`xlsx`/`pptx`/`pdf`/`zip`. Legacy `.doc`/`.xls`, `.rtf`, `.odt`, `.msg`,
   CAD, and anything proprietary are skipped by the filter and, if read, will classify as
   unextractable (limitation 1).
6. **A model upgrade resets coverage.** Entries under a superseded `model_version` read as
   stale, i.e. as misses. A model rollout must be treated as a **new rollout**: turn
   `denyUnclassified` off, upgrade, let the sweep complete under the new version, verify,
   turn it back on. `ml-status` refuses to call an endpoint ready on a sweep from another
   model — deliberately.
7. **Coverage is per-endpoint; the flag is fleet-wide.** There is no per-machine override
   for `denyUnclassified`. One un-swept endpoint in the policy's scope is one endpoint
   denying first reads. Verify the ring, and ideally the slowest members of the estate,
   before enabling centrally.
8. **What `denyUnclassified` does and does not close.** It closes the window in which an
   exfil-channel process reads a document **the model has never seen** — the RustDesk /
   AnyDesk / RDP case this whole feature exists for. It does **not** make the model
   correct, does not widen what the model can read (limitations 1, 2, 5), does not touch
   any egress channel, and does not apply where the on-demand worker is not running. It is
   a *coverage* control layered on the read path, not a new detector.
9. **A cache miss never means "not sensitive."** Worth restating because it is the invariant
   the whole design rests on. A miss produces either today's fingerprint-only answer (flag
   off) or a deny (flag on) — never an allow-because-clean. The cache stores what the
   **model** said; the **policy** decides what that means, at lookup time. That is what
   lets an admin mark a new class sensitive, or move a threshold, and have it take effect
   on the whole estate on the next read instead of invalidating every entry.

---

## Appendix — the one-page command card

```powershell
# Is this endpoint covered? (the pre-flight for denyUnclassified)
.\dlp-agent.exe ml-status
.\dlp-agent.exe ml-status --json          # for fleet tooling; gate on readyForDenyUnclassified
.\dlp-agent.exe ml-status --no-load       # fast; does not load the 256 MB graph
.\dlp-agent.exe ml-status --help

# Did the pipeline start?
Get-Content C:\ProgramData\DLPAgent\logs\dlp-agent.log -Tail 200 |
    Select-String "ML |ml watcher|ml walker|ml classify|verdict cache"

# Has the sweep finished?
Select-String -Path C:\ProgramData\DLPAgent\logs\dlp-agent.log -Pattern "FULL at-rest sweep complete"

# Are reads being denied?
Select-String -Path C:\ProgramData\DLPAgent\logs\dlp-agent.log -Pattern "denyUnclassified"

# Apply a console policy change now instead of waiting up to checkin_interval_seconds
sc stop DLPAgent ; sc start DLPAgent      # elevated

# Back out
#   console -> Classification (ML) -> denyUnclassified OFF -> Save   (<= 5 min to the fleet)
```

`ml-status` is read-only by construction: it classifies nothing, enforces nothing, and
**never opens the live verdict log** — it replays a *copy*, so an operator running it while
the service is mid-write cannot truncate, compact or re-key the endpoint's durability log.
It prints no file name, no content, and no path outside the configured `[ml]` scopes and
model artifacts.
