# OroResea

OroResea is a local, read-only Windows desktop analyzer for Windows Display
Affinity (WDA) evidence in executables and libraries. Point it at one PE file
or a directory tree; it does not launch or modify inspected files.

## What it detects

- Direct PE imports of `SetWindowDisplayAffinity` (high confidence capability)
- Delay-load PE imports of `SetWindowDisplayAffinity`
- Probable runtime resolution through an embedded API name plus
  `GetProcAddress`/`LdrGetProcedureAddress` evidence
- ASCII and UTF-16 API-name strings
- Named `WDA_EXCLUDEFROMCAPTURE` and `WDA_MONITOR` markers
- `GetWindowDisplayAffinity` as informational inspection capability
- PE architecture, SHA-256, and presence of an embedded Authenticode blob
- Search/filtering, drag-and-drop, cancellation, and JSON/CSV/HTML reports

The signature check reports only whether the PE certificate table contains a
blob. It does not validate the trust chain or identify the signer.

## Important limitation

Static evidence is not proof of runtime behavior. A direct import may be used
with `WDA_NONE` to clear protection, while packed, encrypted, downloaded, or
runtime-generated code may hide a protection call. OroResea deliberately uses
the terms *capability* and *evidence* rather than claiming a file is actively
blocking capture.

## Build

```powershell
cargo test
cargo build --release
```

The native executable is written to `target\release\ororesea.exe` for the host
architecture. Cross-build x64 with:

```powershell
cargo build --release --target x86_64-pc-windows-msvc
```

## Safety boundary

OroResea does not inject DLLs, patch processes, clear WDA, bypass capture
controls, disable security software, or execute scanned binaries. Analyze only
software you own or are authorized to inspect.
