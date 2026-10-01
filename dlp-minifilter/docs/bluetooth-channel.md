# Bluetooth file-transfer channel

This implementation targets the Windows built-in Bluetooth file-transfer wizard,
`fsquirt.exe`. It uses the existing minifilter source-read path and the existing
IDM/EDM and ML detectors. It does not intercept arbitrary OBEX/RFCOMM clients,
Bluetooth PAN/tethering, Nearby Sharing, or Phone Link.

## Policy and deployment

1. Apply server migration `023_bluetooth_channel.sql` through the usual migration
   command. It adds `bluetoothMode` to the existing read-deny policy API, with
   Default/group inheritance and the same policy-author permissions and audit.
2. Deploy the updated server and frontend. In **Read-deny policy**, the independent
   **Bluetooth file transfer** section provides Off, Monitor, and Block modes.
   Existing installations default to Off. Older clients omitting this field
   preserve the saved mode.
3. Build, sign, and deploy the matching agent and driver together. The scan wire
   version is now **3**. Bluetooth policy has its own versioned handshake on the
   scanner connection; an incompatible driver is an error, not a successful enable.
   This source change does not install or sign a driver, apply database migrations,
   or change policy on a running endpoint.
4. Start with Monitor on a test endpoint. Validate the matrix below before enabling
   Block on production machines. Confirm the required source volumes are attached.

Bluetooth does not require general read-deny to be enabled or its folders to be
watched. Local volumes are enumerated by volume GUID, including folder-mounted
volumes; mapped network letters are also attempted. Later mounts use InstanceSetup.
Attach failures are logged and mean that volume is **not confirmed protected**.
Attaching for Bluetooth does not enable network write quarantine. A general
read-deny restriction still wins when Bluetooth is only monitoring.

## Decision and enforcement

* A fingerprint match OR a policy-sensitive, successful ML result is sufficient.
  Bluetooth Block mode enforces that sensitivity even if the ML policy's action
  for other channels is Audit. ML must be enabled and labels configured to obtain
  ML coverage; otherwise fingerprinting remains active.
* The synchronous path only looks up ML results and queues missing classification.
  It never runs model inference while the filesystem waits. Missing fingerprints,
  pending/unavailable classification, unreadable content, and incomplete scans
  produce NOVERDICT: Block denies this attempt without caching it as clean.
  A retry can succeed after classification. There is no automatic transfer resume.
* Files exceeding the **4 MiB** kernel content cap are not allowed merely because
  the prefix appears clean. This version denies such unverified transfers in Block
  mode. A full-file verification mechanism is future work.
* The driver identifies the requestor's actual image basename synchronously,
  case-insensitively, using SeLocateProcessImageName. It does not wait for a PID
  poll or consult publisher trust. Existing and newly started wizard processes
  follow the same checks. Renaming the transfer executable or using a different
  client is outside this implementation's identity coverage.
* Known-sensitive source opens are cancelled. Reads are denied before returning
  bytes; data mappings consult the separate Bluetooth stream verdict. Executable
  mappings and the classifier's own internal reads retain their existing bypasses.
* Bluetooth has separate stream verdict/epoch fields and does not trust the
  generic clean/sensitive file-ID rings or write-channel hash cache. Buffered
  reads recheck clean content. Ordinary/paging writes and metadata operations
  invalidate the Bluetooth stream verdict. Pending verdicts are never cached.
* OS runtime assets (`dll`, `exe`, `mui`, `nls`) under the actual resolved
  SystemRoot's System32, SysWOW64, and WinSxS directories are exempt from this
  channel so the wizard can load its code and localization resources. Alternate
  streams are not exempt. This assumes the normal Windows protection of these
  directories; it is not a defence against an administrator modifying OS files.

First detections and cached repeat denies use incident channel `bluetooth`.
Monitor incidents are audited/would-block. Unknown classification is counted by
the existing aggregate unclassified telemetry and debug-logged as Bluetooth;
it is not reported as a positive sensitive-file detection. Byte content is never
included in these logs or incidents.

## Required endpoint acceptance matrix

Use a disposable Windows test endpoint, the matching signed driver/agent, and a
paired receiver. Record the build hashes, policy and bundle versions, source
volumes, incident IDs, and receiver-side byte counts. Unit tests and compilation
do not establish physical Bluetooth coverage.

| Case | Expected in Block mode |
|---|---|
| Registered fingerprint-only document | Transfer denied; Bluetooth fingerprint incident |
| Unregistered document with cached sensitive ML verdict | Denied; Bluetooth ML incident |
| Both detectors sensitive | Denied; both signals retained |
| Complete clean document under 4 MiB | Successful transfer; identical received bytes |
| ML cache miss | Attempt denied; retry follows completed classification |
| Missing model/bundle, encrypted/corrupt input, file over cap | Denied as unverifiable; no false sensitive claim |
| Fresh wizard process, no wait for PID polling | Sensitive first read denied |
| Existing wizard at policy enable; Microsoft publisher trusted | Sensitive read still denied |
| Repeated attempts | Bluetooth repeat incident, not USB |
| Rename/copy sensitive document; edit clean file into sensitive content | Sensitive content denied |
| Desktop, D: drive, folder-mounted local volume, supported network source | Same decisions on successfully attached volumes |
| Clean buffered and memory-mapped reads | Allowed only with valid clean classification |
| Off / Monitor / Block changes, general read-deny off | Independent mode applies; Monitor never claims a block |
| Agent restart/disconnect with persisted Block policy | Unverifiable data stays denied |
| Ordinary local copies and network writes with Bluetooth enabled | Existing channel policies unchanged |

Also test wizard startup, file-picker navigation, receiving files, cancellation,
Windows servicing, concurrent editing, system load, Driver Verifier, and a reboot.
The generic minifilter's PASSIVE-level/reentrancy gates and already-mapped memory
remain architectural limits; this is not a universal transport-level DLP control.
