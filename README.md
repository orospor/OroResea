# OroResea 0.2.0

OroResea is a local, read-only Windows desktop analyzer for capture-protection
evidence and process protection posture. It separates what a PE file declares
before launch from what Windows reports for a running process; neither view is
presented as proof that an application is impossible to capture or inject.

## Analysis modes

### WDA Evidence

Point OroResea at one Windows executable or DLL, or scan a directory tree. The
scanner looks for Windows Display Affinity (WDA) capability without launching
or modifying the inspected files:

- Direct and delay-loaded PE imports of `SetWindowDisplayAffinity`
- Probable runtime resolution through embedded API names plus
  `GetProcAddress` or `LdrGetProcedureAddress` evidence
- ASCII and UTF-16 API-name strings
- Named `WDA_EXCLUDEFROMCAPTURE` and `WDA_MONITOR` markers
- `GetWindowDisplayAffinity` as informational inspection capability
- PE architecture, SHA-256, and embedded certificate-table presence

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

1. Start OroResea and choose **WDA Evidence** or **Protection Posture**.
2. For a pre-launch assessment, choose an executable or DLL and analyze the
   file. OroResea does not start it.
3. For a live assessment, refresh the process list, select the intended PID,
   and take a snapshot. Repeat after a state change when current evidence is
   important.
4. Review unavailable evidence and the limitations before drawing a conclusion,
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
