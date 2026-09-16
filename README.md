# OroResea 0.3.0

OroResea is a local, read-only Windows desktop analyzer for capture-protection
evidence and process protection posture. It separates what a PE file declares
before launch from what Windows reports for a running process; neither view is
presented as proof that an application is impossible to capture or inject.

## Analysis modes

### Static capability scan

Point OroResea at one Windows executable or DLL, or scan a directory tree. The
scanner has three independently selectable categories and never launches or
modifies the inspected files:

- **WDA APIs and markers:** direct and delay-loaded imports, probable dynamic
  bindings, API strings, named WDA modes, and display-affinity inspection.
- **CIG / mitigation APIs:** `SetProcessMitigationPolicy`,
  `GetProcessMitigationPolicy`, and supporting signature-policy markers.
- **DLL search / loading APIs:** `SetDefaultDllDirectories`,
  `SetDllDirectoryW`, `AddDllDirectory`, and `LoadLibrary` variants.

Every result also records PE architecture, SHA-256, and embedded
certificate-table presence. CIG and DLL findings are reported as capabilities;
static API presence does not prove a policy was requested or accepted.

Static evidence is not proof of runtime behavior. An application can import
`SetWindowDisplayAffinity` only to clear protection with `WDA_NONE`, while
packed, encrypted, downloaded, or generated code may hide a protection call.

### Protection Posture

Protection Posture has two complementary targets:

- **Static file assessment** inspects a selected PE before launch. It reports
  declared ASLR, high-entropy ASLR, DEP/NX, Control Flow Guard metadata,
  CET/shadow-stack metadata, and Authenticode trust. On Windows, Authenticode
  trust for an embedded PE signature uses a cache-only `WinVerifyTrust`
  evaluation and does not download revocation data. Catalog-signature
  membership is not evaluated.
- **Live process assessment** lists running processes and takes an on-demand,
  read-only snapshot of the selected process. It reports top-level-window WDA,
  DEP and ASLR, dynamic-code policy, strict-handle checks, extension-point
  policy, CFG/XFG, signature/Code Integrity Guard policy, image-load policy,
  user shadow stacks, process protection/PPL, debugger state, loaded-module
  metadata, and private executable or read-write-execute memory-region counts.

The process list can include all processes or be limited to processes with
visible top-level windows. Names are only labels; select the target by the
observed process and PID rather than assuming a product uses a predictable
executable name.

Some protections are compatibility-sensitive. For example, dynamic-code
restrictions can conflict with JIT runtimes, and executable private memory is
common in browsers and managed applications. OroResea reports those facts with
context instead of treating every absence or executable region as proof of a
vulnerability or injection.

WDA results are observations unless a separate policy baseline defines what a
particular application must enforce. `WDA_NONE` is therefore informational,
all visible windows protected is positive evidence, and mixed or incomplete
visible-window results are warnings.

### OroNimbus lab profile

Protection Posture now includes a dedicated **OroNimbus lab** profile. Choose
the expected WDA mode (`NONE`, `MONITOR`, or `EXCLUDE`) and expected main-PID
CIG state (`off` or `MicrosoftSignedOnly`), select the running PID that owns the
visible OroNimbus window, and take a snapshot.

The profile adds an independently collected correlation section for:

- Process name/path identity evidence and likely main/WDA-owner scope.
- Exact per-window WDA comparison; MONITOR and EXCLUDE are not merged.
- Exact `MicrosoftSignedOnly` bit matching rather than treating every nonzero
  signature policy as OroNimbus CIG.
- Loader-visible presence of the packaged `wda_native.node` bridge.
- An explicit `unverified externally` result for OroNimbus DLL-search
  hardening. Windows `ProcessImageLoadPolicy` is a different control and is not
  used as a substitute readback.

**Find OroNimbus** refreshes the process inventory and applies a convenience
text filter. The operator still selects the intended PID; a process name alone
is not treated as product identity. Chromium children are not assumed to
inherit the main process's WDA or post-bootstrap CIG.

The OroNimbus profile does not rerun the browser's transient unsigned CIG
probe, recover watchdog history, or infer exact renderer/GPU roles. Those are
internal OroNimbus evidence surfaces and remain distinct from OroResea's
external Windows snapshot.

## Access and administrator mode

Standard-user mode is sufficient for many desktop applications. Running
OroResea as administrator can improve access to process paths, mitigation
policies, modules, windows, and memory-region metadata, but elevation does not
override every Windows security boundary. Protected processes, a different
security context or session, and processes that exit during inspection can
still return **Access denied** or **Unavailable**. OroResea keeps those states
distinct from **Disabled** or **Fail** so missing evidence is not misreported.

## Reports

Both WDA scans and Protection Posture assessments can be exported as JSON, CSV,
or a self-contained HTML report. Protection Posture reports keep static, live,
and system-scope findings separate and include the assessment limitations.

## Build and run

Requirements: Windows, Rust with the MSVC toolchain, and the Visual Studio C++
build tools for the target architecture.

```powershell
cargo test --locked
cargo build --release --locked
cargo run --release --locked
```

The native executable is written to `target\release\ororesea.exe` for the host
architecture. Cross-build x64 with:

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --release --locked --target x86_64-pc-windows-msvc
```

The x64 executable is written to
`target\x86_64-pc-windows-msvc\release\ororesea.exe`.

## Use

1. Start OroResea and choose **Static Capabilities** or **Protection Posture**.
2. For a pre-launch assessment, choose an executable or DLL and analyze the
   file. OroResea does not start it.
3. For a live assessment, refresh the process list, select the intended PID,
   and take a snapshot. Repeat after a state change when current evidence is
   important.
4. For OroNimbus, select **OroNimbus lab**, choose the expected WDA/CIG launch
   configuration, select the visible-window owner PID, and snapshot it.
5. Review unavailable evidence and the limitations before drawing a conclusion,
   then export JSON, CSV, or HTML when a report is needed.

## Safety boundary

OroResea opens only the Windows query access needed for observable metadata. It
does not inject DLLs, duplicate target handles, patch or suspend processes,
read target memory contents, clear WDA, change mitigation policies, bypass
capture controls, disable security software, or execute scanned binaries.
Analyze only software and systems you own or are authorized to inspect.

Window titles are not collected. Reports can contain executable and loaded-
module paths, so review an exported report before sharing it. OroResea does not
transmit a scan or snapshot automatically.

## Limitations

- Static metadata describes declared capability and build configuration, not
  every runtime code path or effective policy.
- A live assessment is a point-in-time snapshot. Process, window, module, and
  memory state can change immediately after collection.
- Access-denied and unavailable results are gaps in observation, not evidence
  that a protection is absent.
- A snapshot cannot prove which Windows Defender Application Control (WDAC)
  policy decisions governed every loaded image. That requires system policy
  inspection and Code Integrity event telemetry.
- Historical `OpenProcess` and process-handle access cannot be reconstructed
  from a snapshot. Continuous ETW, auditing, EDR, or driver-backed telemetry is
  required for that history.
- WDA affects compatible capture paths and Windows versions; it is not a general
  anti-injection boundary.
- No user-mode snapshot can establish that a process is "uninjectable," rule
  out privileged or kernel-level interference, or replace a controlled security
  review.
