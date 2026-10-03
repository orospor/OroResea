//! Read-only, point-in-time inspection of a running process on Windows.
//!
//! This module deliberately performs no injection, remote allocation, memory
//! reads, memory writes, handle duplication, or mitigation changes. Results are
//! observations, not proof that a process cannot be tampered with.

use serde::{Deserialize, Serialize};

/// The state of one piece of collected evidence.
///
/// `Enabled` and `Disabled` are reserved for boolean/security controls.
/// `Available` means a non-boolean value was read successfully. A denied or
/// unsupported query is never represented as `Disabled`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Enabled,
    Disabled,
    Available,
    Unavailable,
    AccessDenied,
    Error,
}

/// A value plus its collection state and, when applicable, its Win32 error.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Evidence<T> {
    pub state: EvidenceState,
    pub value: Option<T>,
    pub error_code: Option<u32>,
    pub message: Option<String>,
}

impl<T> Evidence<T> {
    fn available(value: T) -> Self {
        Self {
            state: EvidenceState::Available,
            value: Some(value),
            error_code: None,
            message: None,
        }
    }

    fn boolean(enabled: bool, value: T) -> Self {
        Self {
            state: if enabled {
                EvidenceState::Enabled
            } else {
                EvidenceState::Disabled
            },
            value: Some(value),
            error_code: None,
            message: None,
        }
    }

    #[cfg(not(windows))]
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            state: EvidenceState::Unavailable,
            value: None,
            error_code: None,
            message: Some(message.into()),
        }
    }

    fn failed(state: EvidenceState, error_code: Option<u32>, message: impl Into<String>) -> Self {
        debug_assert!(matches!(
            state,
            EvidenceState::Unavailable | EvidenceState::AccessDenied | EvidenceState::Error
        ));
        Self {
            state,
            value: None,
            error_code,
            message: Some(message.into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WindowCounts {
    pub top_level: u32,
    pub visible: u32,
}

/// A lightweight row suitable for a process picker.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessSummary {
    pub pid: u32,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub executable_name: String,
    pub executable_path: Evidence<String>,
    pub windows: Evidence<WindowCounts>,
    /// Present only when the executable path or a loaded JVM module supports
    /// treating this process as a Java host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub java_app: Option<Evidence<JavaAppIdentity>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaLaunchKind {
    Jar,
    Module,
    MainClass,
    SourceFile,
    Unknown,
}

impl JavaLaunchKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Jar => "JAR",
            Self::Module => "module",
            Self::MainClass => "main class",
            Self::SourceFile => "source file",
            Self::Unknown => "unknown target",
        }
    }
}

/// The JVM application target, without the remaining command-line arguments.
/// Launcher arguments can contain credentials, so they are never retained here.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JavaAppIdentity {
    pub launch_kind: JavaLaunchKind,
    pub launch_target: Option<String>,
    pub identity_basis: String,
    /// True only when the selected process's module inventory contains jvm.dll.
    pub runtime_confirmed: bool,
    pub command_line_state: EvidenceState,
    pub command_line_message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NamedFlag {
    pub name: String,
    pub enabled: bool,
}

/// One effective process-mitigation policy returned by Windows.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MitigationFinding {
    pub state: EvidenceState,
    pub raw_flags: Option<u32>,
    pub flags: Vec<NamedFlag>,
    pub error_code: Option<u32>,
    pub message: Option<String>,
}

impl MitigationFinding {
    #[cfg(not(windows))]
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            state: EvidenceState::Unavailable,
            raw_flags: None,
            flags: Vec::new(),
            error_code: None,
            message: Some(message.into()),
        }
    }

    fn failed(state: EvidenceState, error_code: Option<u32>, message: impl Into<String>) -> Self {
        Self {
            state,
            raw_flags: None,
            flags: Vec::new(),
            error_code,
            message: Some(message.into()),
        }
    }

    fn from_flags(raw_flags: u32, enforcement_mask: u32, definitions: &[(&str, u32)]) -> Self {
        Self::from_flags_with_state(
            raw_flags,
            if raw_flags & enforcement_mask != 0 {
                EvidenceState::Enabled
            } else {
                EvidenceState::Disabled
            },
            definitions,
        )
    }

    fn from_flags_with_state(
        raw_flags: u32,
        state: EvidenceState,
        definitions: &[(&str, u32)],
    ) -> Self {
        Self {
            state,
            raw_flags: Some(raw_flags),
            flags: definitions
                .iter()
                .map(|(name, mask)| NamedFlag {
                    name: (*name).to_owned(),
                    enabled: raw_flags & mask != 0,
                })
                .collect(),
            error_code: None,
            message: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MitigationPosture {
    pub dep: MitigationFinding,
    pub aslr: MitigationFinding,
    pub dynamic_code: MitigationFinding,
    pub strict_handle_check: MitigationFinding,
    pub extension_point_disable: MitigationFinding,
    pub control_flow_guard: MitigationFinding,
    pub signature_policy_cig: MitigationFinding,
    pub image_load: MitigationFinding,
    pub user_shadow_stack: MitigationFinding,
}

impl MitigationPosture {
    #[cfg(not(windows))]
    fn unavailable(message: &str) -> Self {
        Self {
            dep: MitigationFinding::unavailable(message),
            aslr: MitigationFinding::unavailable(message),
            dynamic_code: MitigationFinding::unavailable(message),
            strict_handle_check: MitigationFinding::unavailable(message),
            extension_point_disable: MitigationFinding::unavailable(message),
            control_flow_guard: MitigationFinding::unavailable(message),
            signature_policy_cig: MitigationFinding::unavailable(message),
            image_load: MitigationFinding::unavailable(message),
            user_shadow_stack: MitigationFinding::unavailable(message),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProtectionLevel {
    pub raw_level: u32,
    pub name: String,
    /// `None` means Windows returned a protection level this build does not
    /// recognize, so the collector cannot safely classify it.
    pub is_protected: Option<bool>,
    /// `None` means the raw protection level is not recognized.
    pub is_ppl: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModuleInventory {
    pub count: u32,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MemoryRegionSummary {
    pub scanned_region_count: u64,
    pub executable_private_region_count: u64,
    pub executable_private_bytes: u64,
    pub rwx_region_count: u64,
    pub rwx_bytes: u64,
    pub private_rwx_region_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayAffinityKind {
    None,
    Monitor,
    ExcludeFromCapture,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DisplayAffinity {
    pub raw_value: u32,
    pub kind: DisplayAffinityKind,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WindowPosture {
    /// Numeric HWND value. It is meaningful only for the current desktop/session.
    pub hwnd: u64,
    /// Intentionally empty. Window title text is not collected for privacy.
    pub title: String,
    pub visible: bool,
    pub display_affinity: Evidence<DisplayAffinity>,
}

/// Full point-in-time observation for a selected process.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessInspection {
    pub pid: u32,
    pub executable_name: Evidence<String>,
    pub executable_path: Evidence<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub java_app: Option<Evidence<JavaAppIdentity>>,
    pub mitigations: MitigationPosture,
    pub protection_level: Evidence<ProtectionLevel>,
    /// `Enabled` means a debugger was reported present; `Disabled` means none
    /// was reported at the instant of this query.
    pub remote_debugger_present: Evidence<bool>,
    pub modules: Evidence<ModuleInventory>,
    pub memory: Evidence<MemoryRegionSummary>,
    pub windows: Evidence<Vec<WindowPosture>>,
}

/// True when the running build contains the Windows collector.
pub const fn is_supported() -> bool {
    cfg!(windows)
}

/// Enumerate running processes. Window counts make it possible to distinguish
/// GUI/user-visible processes without dropping background processes.
pub fn enumerate_running_processes() -> Evidence<Vec<ProcessSummary>> {
    platform::enumerate_running_processes()
}

/// Enumerate only processes with at least one currently visible top-level HWND.
pub fn enumerate_user_visible_processes() -> Evidence<Vec<ProcessSummary>> {
    match enumerate_running_processes() {
        Evidence {
            state: EvidenceState::Available,
            value: Some(mut processes),
            ..
        } => {
            processes.retain(|process| {
                process
                    .windows
                    .value
                    .as_ref()
                    .is_some_and(|counts| counts.visible > 0)
            });
            Evidence::available(processes)
        }
        other => other,
    }
}

/// Inspect a selected PID without changing or reading its memory contents.
pub fn inspect_process(pid: u32) -> ProcessInspection {
    platform::inspect_process(pid)
}

fn classify_aslr_state(raw_flags: u32) -> EvidenceState {
    // Bottom-up randomization, forced relocation, and high-entropy VA are the
    // effective randomization controls. DisallowStrippedImages alone does not
    // randomize anything.
    if raw_flags & 0x07 != 0 {
        EvidenceState::Enabled
    } else {
        EvidenceState::Disabled
    }
}

fn classify_dynamic_code_state(raw_flags: u32) -> EvidenceState {
    const PROHIBIT_DYNAMIC_CODE: u32 = 0x01;
    const ALLOW_THREAD_OPT_OUT: u32 = 0x02;
    const ALLOW_REMOTE_DOWNGRADE: u32 = 0x04;

    if raw_flags & PROHIBIT_DYNAMIC_CODE == 0 {
        EvidenceState::Disabled
    } else if raw_flags & (ALLOW_THREAD_OPT_OUT | ALLOW_REMOTE_DOWNGRADE) != 0 {
        // The prohibition exists but is intentionally weakenable. This is
        // useful evidence, but not equivalent to full enforcement.
        EvidenceState::Available
    } else {
        EvidenceState::Enabled
    }
}

fn classify_display_affinity_state(
    raw_value: u32,
    none: u32,
    monitor: u32,
    exclude_from_capture: u32,
) -> EvidenceState {
    if raw_value == none {
        EvidenceState::Disabled
    } else if raw_value == monitor || raw_value == exclude_from_capture {
        EvidenceState::Enabled
    } else {
        EvidenceState::Available
    }
}

fn is_java_launcher_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("java.exe") || name.eq_ignore_ascii_case("javaw.exe")
}

fn is_java_runtime_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    lower.ends_with("\\bin\\java.exe") || lower.ends_with("\\bin\\javaw.exe")
}

fn has_jvm_module(modules: &Evidence<ModuleInventory>) -> bool {
    modules.value.as_ref().is_some_and(|inventory| {
        inventory.paths.iter().any(|path| {
            path.rsplit(['\\', '/'])
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("jvm.dll"))
        })
    })
}

// Split only to locate a Java launcher target. No complete command line or
// application arguments are retained in the result or exported assessment.
fn windows_command_line_tokens(command_line: &str) -> Vec<String> {
    let chars: Vec<char> = command_line.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index == chars.len() {
            break;
        }
        let mut token = String::new();
        let mut quoted = false;
        while index < chars.len() && (quoted || !chars[index].is_whitespace()) {
            if chars[index] == '\\' {
                let start = index;
                while index < chars.len() && chars[index] == '\\' {
                    index += 1;
                }
                let slashes = index - start;
                if index < chars.len() && chars[index] == '"' {
                    token.extend(std::iter::repeat_n('\\', slashes / 2));
                    if slashes % 2 == 1 {
                        token.push('"');
                        index += 1;
                    }
                } else {
                    token.extend(std::iter::repeat_n('\\', slashes));
                }
                if index >= chars.len() || chars[index] != '"' {
                    continue;
                }
            }
            if chars[index] == '"' {
                if quoted && index + 1 < chars.len() && chars[index + 1] == '"' {
                    token.push('"');
                    index += 2;
                } else {
                    quoted = !quoted;
                    index += 1;
                }
            } else {
                token.push(chars[index]);
                index += 1;
            }
        }
        tokens.push(token);
    }
    tokens
}

fn parse_java_launch_target(command_line: &str) -> (JavaLaunchKind, Option<String>) {
    let tokens = windows_command_line_tokens(command_line);
    let mut arguments = tokens.iter().skip(1).peekable();
    while let Some(argument) = arguments.next() {
        let value = argument.as_str();
        if matches!(value, "-jar" | "-m" | "--module") {
            let kind = if value == "-jar" {
                JavaLaunchKind::Jar
            } else {
                JavaLaunchKind::Module
            };
            return (
                kind,
                arguments
                    .next()
                    .filter(|target| !target.is_empty())
                    .cloned(),
            );
        }
        if let Some(target) = value.strip_prefix("--module=") {
            return (JavaLaunchKind::Module, Some(target.to_owned()));
        }
        if value.starts_with('@') {
            // An argument file may supply the actual launch target. Do not
            // claim that a later token names the application.
            break;
        }
        if matches!(
            value,
            "-cp"
                | "-classpath"
                | "--class-path"
                | "-p"
                | "--module-path"
                | "--upgrade-module-path"
                | "--add-modules"
                | "--limit-modules"
                | "--add-exports"
                | "--add-opens"
                | "--add-reads"
                | "--patch-module"
                | "--enable-native-access"
                | "--source"
        ) {
            if arguments.next().is_none() {
                break;
            }
            continue;
        }
        if value.starts_with("--") && value.contains('=') {
            continue;
        }
        if value.starts_with("-D")
            || value.starts_with("-X")
            || value.starts_with("-XX:")
            || value.starts_with("-javaagent:")
            || value.starts_with("-agentlib:")
            || value.starts_with("-agentpath:")
            || matches!(
                value,
                "-server"
                    | "-client"
                    | "-ea"
                    | "-da"
                    | "-esa"
                    | "-dsa"
                    | "--enable-preview"
                    | "--dry-run"
            )
        {
            continue;
        }
        if value.starts_with('-') || value.is_empty() {
            break;
        }
        let kind = if value.to_ascii_lowercase().ends_with(".java") {
            JavaLaunchKind::SourceFile
        } else {
            JavaLaunchKind::MainClass
        };
        return (kind, Some(value.to_owned()));
    }
    (JavaLaunchKind::Unknown, None)
}

fn parse_jpackage_config(contents: &str) -> (JavaLaunchKind, Option<String>) {
    let mut in_application = false;
    let mut main_class = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_application = line.eq_ignore_ascii_case("[Application]");
            continue;
        }
        if !in_application {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if key.trim().eq_ignore_ascii_case("app.mainmodule") {
            return (JavaLaunchKind::Module, Some(value.to_owned()));
        }
        if key.trim().eq_ignore_ascii_case("app.mainclass") {
            main_class = Some(value.to_owned());
        }
    }
    match main_class {
        Some(class) => (JavaLaunchKind::MainClass, Some(class)),
        None => (JavaLaunchKind::Unknown, None),
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        collections::HashMap,
        ffi::c_void,
        io::Read,
        mem::size_of,
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
        process::Command,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_FUNCTION,
            ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_PARTIAL_COPY, ERROR_PROC_NOT_FOUND,
            GetLastError, HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM, SetLastError,
        },
        System::{
            Diagnostics::{
                Debug::CheckRemoteDebuggerPresent,
                ToolHelp::{
                    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                    PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPMODULE,
                    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
                },
            },
            Memory::{
                MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, VirtualQueryEx,
            },
            SystemServices::{
                PROCESS_MITIGATION_ASLR_POLICY, PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY, PROCESS_MITIGATION_DEP_POLICY,
                PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
                PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
                PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
                PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
                PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY,
            },
            Threading::{
                GetProcessInformation, GetProcessMitigationPolicy, OpenProcess,
                PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION, PROTECTION_LEVEL_ANTIMALWARE_LIGHT,
                PROTECTION_LEVEL_AUTHENTICODE, PROTECTION_LEVEL_CODEGEN_LIGHT,
                PROTECTION_LEVEL_LSA_LIGHT, PROTECTION_LEVEL_NONE, PROTECTION_LEVEL_PPL_APP,
                PROTECTION_LEVEL_WINDOWS, PROTECTION_LEVEL_WINDOWS_LIGHT, PROTECTION_LEVEL_WINTCB,
                PROTECTION_LEVEL_WINTCB_LIGHT, ProcessASLRPolicy, ProcessControlFlowGuardPolicy,
                ProcessDEPPolicy, ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy,
                ProcessImageLoadPolicy, ProcessProtectionLevelInfo, ProcessSignaturePolicy,
                ProcessStrictHandleCheckPolicy, ProcessUserShadowStackPolicy,
                QueryFullProcessImageNameW,
            },
        },
        UI::WindowsAndMessaging::{
            EnumWindows, GetWindowDisplayAffinity, GetWindowThreadProcessId, IsWindowVisible,
            WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR, WDA_NONE,
        },
    };

    const ERROR_BAD_LENGTH_CODE: u32 = 24;
    const ERROR_NO_MORE_FILES_CODE: u32 = 18;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct CimProcess {
        process_id: u32,
        executable_path: Option<String>,
        command_line: Option<String>,
    }

    struct CimFailure {
        state: EvidenceState,
        message: &'static str,
    }

    fn query_cim_processes(filter: &str) -> Result<Vec<CimProcess>, CimFailure> {
        // These filters are constructed only from numeric PIDs or fixed Java
        // executable names. The raw command lines stay in this local result
        // until a launch target is parsed; they are never exported.
        let script = format!(
            "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $rows=@(Get-CimInstance -ClassName Win32_Process -Filter \"{filter}\" -Property ProcessId,ExecutablePath,CommandLine | Select-Object ProcessId,ExecutablePath,CommandLine); ConvertTo-Json -InputObject $rows -Compress"
        );
        let root = std::env::var_os("SystemRoot").ok_or(CimFailure {
            state: EvidenceState::Unavailable,
            message: "Windows system directory is unavailable for CIM query",
        })?;
        let powershell = PathBuf::from(root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let output = Command::new(powershell)
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|_| CimFailure {
                state: EvidenceState::Unavailable,
                message: "Windows PowerShell could not start for CIM query",
            })?;
        if !output.status.success() {
            let denied = String::from_utf8_lossy(&output.stderr)
                .to_ascii_lowercase()
                .contains("access is denied");
            return Err(CimFailure {
                state: if denied {
                    EvidenceState::AccessDenied
                } else {
                    EvidenceState::Unavailable
                },
                message: "Win32_Process command-line query failed",
            });
        }
        serde_json::from_slice(&output.stdout).map_err(|_| CimFailure {
            state: EvidenceState::Error,
            message: "Win32_Process returned an unreadable command-line response",
        })
    }

    fn jpackage_image_target(path: &str) -> Option<(JavaLaunchKind, Option<String>)> {
        let launcher = Path::new(path);
        if !launcher
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        {
            return None;
        }
        let parent = launcher.parent()?;
        let stem = launcher.file_stem()?.to_str()?;
        let cfg = parent.join("app").join(format!("{stem}.cfg"));
        let jvm = parent
            .join("runtime")
            .join("bin")
            .join("server")
            .join("jvm.dll");
        if !jvm.is_file() || !cfg.is_file() {
            return None;
        }
        // A generated jpackage launcher config is small. A bound avoids
        // consuming unbounded data from an unrelated or replaced file.
        let mut contents = String::new();
        std::fs::File::open(cfg)
            .ok()?
            .take(64 * 1024 + 1)
            .read_to_string(&mut contents)
            .ok()?;
        if contents.len() > 64 * 1024 {
            return None;
        }
        Some(parse_jpackage_config(&contents))
    }

    fn java_identity(
        executable_path: &Evidence<String>,
        modules: Option<&Evidence<ModuleInventory>>,
        cim: Result<Option<&CimProcess>, &CimFailure>,
    ) -> Option<Evidence<JavaAppIdentity>> {
        let launcher_path = executable_path
            .value
            .as_deref()
            .is_some_and(is_java_runtime_path);
        let loaded_jvm = modules.is_some_and(has_jvm_module);
        let packaged = executable_path
            .value
            .as_deref()
            .and_then(jpackage_image_target);
        if !launcher_path && !loaded_jvm && packaged.is_none() {
            return None;
        }
        let identity_basis = if loaded_jvm && packaged.is_some() {
            "Loaded jvm.dll module and jpackage launcher config"
        } else if loaded_jvm {
            "Loaded jvm.dll module"
        } else if packaged.is_some() {
            "jpackage launcher config and bundled runtime image"
        } else {
            "Java runtime launcher path"
        };
        let (command_line_state, command_line_message, launch_kind, launch_target) = match cim {
            Err(error) => (
                error.state,
                Some(error.message.to_owned()),
                JavaLaunchKind::Unknown,
                None,
            ),
            Ok(None) => (
                EvidenceState::Unavailable,
                Some("PID was not found by Win32_Process during command-line query".to_owned()),
                JavaLaunchKind::Unknown,
                None,
            ),
            Ok(Some(process)) => {
                let same_image = executable_path.value.as_deref().is_some_and(|path| {
                    process
                        .executable_path
                        .as_deref()
                        .is_some_and(|cim_path| path.eq_ignore_ascii_case(cim_path))
                });
                if !same_image {
                    (
                        EvidenceState::Unavailable,
                        Some(
                            "Process image changed or could not be matched during CIM query"
                                .to_owned(),
                        ),
                        JavaLaunchKind::Unknown,
                        None,
                    )
                } else if let Some(command_line) = process.command_line.as_deref() {
                    let (kind, target) = if let Some((kind, target)) = packaged.as_ref() {
                        (*kind, target.clone())
                    } else if launcher_path {
                        parse_java_launch_target(command_line)
                    } else {
                        // A custom jpackage launcher passes its own arguments;
                        // a bare token cannot safely be called a Java main class.
                        (JavaLaunchKind::Unknown, None)
                    };
                    (
                        EvidenceState::Available,
                        if target.is_none() {
                            Some("The Java launch target could not be inferred from the command line".to_owned())
                        } else {
                            None
                        },
                        kind,
                        target,
                    )
                } else {
                    (
                        EvidenceState::Unavailable,
                        Some("Win32_Process did not expose the command line".to_owned()),
                        JavaLaunchKind::Unknown,
                        None,
                    )
                }
            }
        };
        let (launch_kind, launch_target) = if launch_target.is_none() {
            packaged.unwrap_or((launch_kind, launch_target))
        } else {
            (launch_kind, launch_target)
        };
        Some(Evidence::available(JavaAppIdentity {
            launch_kind,
            launch_target,
            identity_basis: identity_basis.to_owned(),
            runtime_confirmed: loaded_jvm,
            command_line_state,
            command_line_message,
        }))
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: this type owns the valid handle and closes it exactly once.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    struct WinFailure {
        code: u32,
        unsupported_if_invalid_parameter: bool,
    }

    impl WinFailure {
        fn new(code: u32) -> Self {
            Self {
                code,
                unsupported_if_invalid_parameter: false,
            }
        }

        fn policy(code: u32) -> Self {
            Self {
                code,
                unsupported_if_invalid_parameter: true,
            }
        }

        fn state(self) -> EvidenceState {
            if self.code == ERROR_ACCESS_DENIED {
                EvidenceState::AccessDenied
            } else if self.code == ERROR_NOT_SUPPORTED
                || self.code == ERROR_CALL_NOT_IMPLEMENTED
                || self.code == ERROR_INVALID_FUNCTION
                || self.code == ERROR_PROC_NOT_FOUND
                || self.code == ERROR_PARTIAL_COPY
                || (self.unsupported_if_invalid_parameter && self.code == ERROR_INVALID_PARAMETER)
            {
                EvidenceState::Unavailable
            } else {
                EvidenceState::Error
            }
        }

        fn describe(self, operation: &str) -> String {
            let detail = if self.code == 0 {
                "Win32 did not provide an error code".to_owned()
            } else {
                std::io::Error::from_raw_os_error(self.code as i32).to_string()
            };
            format!("{operation}: {detail}")
        }

        fn evidence<T>(self, operation: &str) -> Evidence<T> {
            Evidence::failed(self.state(), Some(self.code), self.describe(operation))
        }

        fn mitigation(self, operation: &str) -> MitigationFinding {
            MitigationFinding::failed(self.state(), Some(self.code), self.describe(operation))
        }
    }

    fn open_process(access: u32, pid: u32) -> Result<OwnedHandle, WinFailure> {
        // SAFETY: OpenProcess does not dereference caller-provided pointers.
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            // SAFETY: GetLastError has no preconditions.
            Err(WinFailure::new(unsafe { GetLastError() }))
        } else {
            Ok(OwnedHandle(handle))
        }
    }

    fn create_snapshot(flags: u32, pid: u32) -> Result<OwnedHandle, WinFailure> {
        let mut last_error = 0;
        for _ in 0..8 {
            // SAFETY: CreateToolhelp32Snapshot takes values only.
            let handle = unsafe { CreateToolhelp32Snapshot(flags, pid) };
            if handle != INVALID_HANDLE_VALUE {
                return Ok(OwnedHandle(handle));
            }
            // SAFETY: GetLastError has no preconditions.
            last_error = unsafe { GetLastError() };
            if last_error != ERROR_BAD_LENGTH_CODE {
                break;
            }
        }
        Err(WinFailure::new(last_error))
    }

    fn wide_string(buffer: &[u16]) -> String {
        let length = buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..length])
    }

    fn query_image_path(pid: u32) -> Evidence<String> {
        let process = match open_process(PROCESS_QUERY_LIMITED_INFORMATION, pid) {
            Ok(process) => process,
            Err(error) => return error.evidence("OpenProcess for executable path"),
        };

        let mut buffer = vec![0u16; 32_768];
        let mut length = buffer.len() as u32;
        // SAFETY: the writable UTF-16 buffer is valid for `length` elements.
        let succeeded = unsafe {
            QueryFullProcessImageNameW(process.raw(), 0, buffer.as_mut_ptr(), &mut length)
        };
        if succeeded == 0 {
            // SAFETY: GetLastError has no preconditions.
            return WinFailure::new(unsafe { GetLastError() })
                .evidence("QueryFullProcessImageNameW");
        }
        buffer.truncate(length as usize);
        Evidence::available(String::from_utf16_lossy(&buffer))
    }

    #[derive(Clone)]
    struct ProcessEntry {
        pid: u32,
        parent_pid: u32,
        thread_count: u32,
        name: String,
    }

    fn process_entries() -> Result<Vec<ProcessEntry>, WinFailure> {
        let snapshot = create_snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        // SAFETY: `entry` has the documented size and remains writable.
        if unsafe { Process32FirstW(snapshot.raw(), &mut entry) } == 0 {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_FILES_CODE {
                return Ok(Vec::new());
            }
            return Err(WinFailure::new(code));
        }

        let mut processes = Vec::new();
        loop {
            processes.push(ProcessEntry {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
                thread_count: entry.cntThreads,
                name: wide_string(&entry.szExeFile),
            });

            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            // SAFETY: `entry` has the documented size and remains writable.
            if unsafe { Process32NextW(snapshot.raw(), &mut entry) } == 0 {
                // SAFETY: GetLastError has no preconditions.
                let code = unsafe { GetLastError() };
                if code == ERROR_NO_MORE_FILES_CODE {
                    break;
                }
                return Err(WinFailure::new(code));
            }
        }
        Ok(processes)
    }

    unsafe extern "system" fn count_window_callback(hwnd: HWND, lparam: LPARAM) -> i32 {
        // SAFETY: EnumWindows invokes this callback synchronously while the map
        // referenced by lparam remains alive and exclusively borrowed.
        let counts = unsafe { &mut *(lparam as *mut HashMap<u32, WindowCounts>) };
        let mut pid = 0u32;
        // SAFETY: `pid` is a valid writable u32 and hwnd is supplied by Windows.
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut pid);
        }
        if pid != 0 {
            let count = counts.entry(pid).or_insert(WindowCounts {
                top_level: 0,
                visible: 0,
            });
            count.top_level = count.top_level.saturating_add(1);
            // SAFETY: hwnd is supplied by Windows.
            if unsafe { IsWindowVisible(hwnd) } != 0 {
                count.visible = count.visible.saturating_add(1);
            }
        }
        1
    }

    fn window_counts() -> Result<HashMap<u32, WindowCounts>, WinFailure> {
        let mut counts = HashMap::new();
        // SAFETY: lparam points to `counts` for the duration of this synchronous call.
        unsafe {
            SetLastError(0);
            if EnumWindows(
                Some(count_window_callback),
                &mut counts as *mut HashMap<u32, WindowCounts> as LPARAM,
            ) == 0
            {
                let code = GetLastError();
                // Some non-interactive window stations report zero with no
                // error when there are no enumerable desktop windows.
                if code != 0 {
                    return Err(WinFailure::new(code));
                }
            }
        }
        Ok(counts)
    }

    pub(super) fn enumerate_running_processes() -> Evidence<Vec<ProcessSummary>> {
        let entries = match process_entries() {
            Ok(entries) => entries,
            Err(error) => return error.evidence("Create/enumerate process snapshot"),
        };
        let counts = window_counts();

        let mut processes: Vec<_> = entries
            .into_iter()
            .map(|entry| {
                let windows = match &counts {
                    Ok(counts) => Evidence::available(counts.get(&entry.pid).cloned().unwrap_or(
                        WindowCounts {
                            top_level: 0,
                            visible: 0,
                        },
                    )),
                    Err(error) => error.evidence("EnumWindows for process list"),
                };
                ProcessSummary {
                    pid: entry.pid,
                    parent_pid: entry.parent_pid,
                    thread_count: entry.thread_count,
                    executable_name: entry.name,
                    executable_path: query_image_path(entry.pid),
                    windows,
                    java_app: None,
                }
            })
            .collect();

        let cim = processes
            .iter()
            .any(|process| is_java_launcher_name(&process.executable_name))
            .then(|| query_cim_processes("Name = 'java.exe' OR Name = 'javaw.exe'"));
        for process in &mut processes {
            let is_named_launcher = is_java_launcher_name(&process.executable_name);
            let runtime_path = process
                .executable_path
                .value
                .as_deref()
                .is_some_and(is_java_runtime_path);
            let packaged = process
                .executable_path
                .value
                .as_deref()
                .and_then(jpackage_image_target)
                .is_some();
            if !is_named_launcher && !packaged {
                continue;
            }
            let modules = if is_named_launcher && !runtime_path && !packaged {
                Some(query_modules(process.pid))
            } else {
                None
            };
            let row = match &cim {
                Some(result) if is_named_launcher => result
                    .as_ref()
                    .map(|rows| rows.iter().find(|row| row.process_id == process.pid)),
                _ => Ok(None),
            };
            process.java_app = java_identity(&process.executable_path, modules.as_ref(), row);
        }

        processes.sort_by(|left, right| {
            let left_visible = left
                .windows
                .value
                .as_ref()
                .map_or(0, |counts| counts.visible);
            let right_visible = right
                .windows
                .value
                .as_ref()
                .map_or(0, |counts| counts.visible);
            right_visible
                .cmp(&left_visible)
                .then_with(|| {
                    left.executable_name
                        .to_lowercase()
                        .cmp(&right.executable_name.to_lowercase())
                })
                .then_with(|| left.pid.cmp(&right.pid))
        });
        Evidence::available(processes)
    }

    fn process_name(pid: u32, path: &Evidence<String>) -> Evidence<String> {
        if let Some(path) = &path.value
            && let Some(name) = Path::new(path).file_name()
        {
            return Evidence::available(name.to_string_lossy().into_owned());
        }
        match process_entries() {
            Ok(entries) => entries
                .into_iter()
                .find(|entry| entry.pid == pid)
                .map(|entry| Evidence::available(entry.name))
                .unwrap_or_else(|| Evidence::failed(EvidenceState::Error, None, "PID not found")),
            Err(error) => error.evidence("Create/enumerate process snapshot for process name"),
        }
    }

    unsafe fn query_policy<T: Default>(process: HANDLE, policy: i32) -> Result<T, WinFailure> {
        let mut value = T::default();
        // SAFETY: `value` is an initialized, writable buffer of the exact policy type.
        let succeeded = unsafe {
            GetProcessMitigationPolicy(
                process,
                policy,
                &mut value as *mut T as *mut c_void,
                size_of::<T>(),
            )
        };
        if succeeded == 0 {
            // SAFETY: GetLastError has no preconditions.
            Err(WinFailure::policy(unsafe { GetLastError() }))
        } else {
            Ok(value)
        }
    }

    fn mitigation_from_result<T>(
        result: Result<T, WinFailure>,
        operation: &str,
        extract_flags: impl FnOnce(T) -> u32,
        enforcement_mask: u32,
        definitions: &[(&str, u32)],
    ) -> MitigationFinding {
        match result {
            Ok(value) => {
                MitigationFinding::from_flags(extract_flags(value), enforcement_mask, definitions)
            }
            Err(error) => error.mitigation(operation),
        }
    }

    fn query_mitigations(process: HANDLE) -> MitigationPosture {
        // SAFETY: every call uses the matching documented policy structure.
        unsafe {
            let dep = match query_policy::<PROCESS_MITIGATION_DEP_POLICY>(process, ProcessDEPPolicy)
            {
                Ok(policy) => {
                    let raw = policy.Anonymous.Flags;
                    let mut finding = MitigationFinding::from_flags(
                        raw,
                        0x1,
                        &[("enable", 0x1), ("disable_atl_thunk_emulation", 0x2)],
                    );
                    finding.flags.push(NamedFlag {
                        name: "permanent".to_owned(),
                        enabled: policy.Permanent,
                    });
                    finding
                }
                Err(error) => error.mitigation("GetProcessMitigationPolicy(DEP)"),
            };

            let aslr =
                match query_policy::<PROCESS_MITIGATION_ASLR_POLICY>(process, ProcessASLRPolicy) {
                    Ok(policy) => {
                        let raw = policy.Anonymous.Flags;
                        MitigationFinding::from_flags_with_state(
                            raw,
                            classify_aslr_state(raw),
                            &[
                                ("enable_bottom_up_randomization", 0x1),
                                ("enable_force_relocate_images", 0x2),
                                ("enable_high_entropy", 0x4),
                                ("disallow_stripped_images", 0x8),
                            ],
                        )
                    }
                    Err(error) => error.mitigation("GetProcessMitigationPolicy(ASLR)"),
                };
            let dynamic_code = match query_policy::<PROCESS_MITIGATION_DYNAMIC_CODE_POLICY>(
                process,
                ProcessDynamicCodePolicy,
            ) {
                Ok(policy) => {
                    let raw = policy.Anonymous.Flags;
                    let mut finding = MitigationFinding::from_flags_with_state(
                        raw,
                        classify_dynamic_code_state(raw),
                        &[
                            ("prohibit_dynamic_code", 0x1),
                            ("allow_thread_opt_out", 0x2),
                            ("allow_remote_downgrade", 0x4),
                            ("audit_prohibit_dynamic_code", 0x8),
                        ],
                    );
                    if finding.state == EvidenceState::Available {
                        finding.message = Some(
                            "dynamic-code prohibition is weakened by thread opt-out and/or remote downgrade"
                                .to_owned(),
                        );
                    }
                    finding
                }
                Err(error) => error.mitigation("GetProcessMitigationPolicy(dynamic code)"),
            };
            let strict_handle_check = mitigation_from_result(
                query_policy::<PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY>(
                    process,
                    ProcessStrictHandleCheckPolicy,
                ),
                "GetProcessMitigationPolicy(strict handle check)",
                |policy| policy.Anonymous.Flags,
                0x3,
                &[
                    ("raise_exception_on_invalid_handle", 0x1),
                    ("handle_exceptions_permanently_enabled", 0x2),
                ],
            );
            let extension_point_disable = mitigation_from_result(
                query_policy::<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>(
                    process,
                    ProcessExtensionPointDisablePolicy,
                ),
                "GetProcessMitigationPolicy(extension points)",
                |policy| policy.Anonymous.Flags,
                0x1,
                &[("disable_extension_points", 0x1)],
            );
            let control_flow_guard = mitigation_from_result(
                query_policy::<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>(
                    process,
                    ProcessControlFlowGuardPolicy,
                ),
                "GetProcessMitigationPolicy(CFG)",
                |policy| policy.Anonymous.Flags,
                0x1,
                &[
                    ("enable_control_flow_guard", 0x1),
                    ("enable_export_suppression", 0x2),
                    ("strict_mode", 0x4),
                    ("enable_xfg", 0x8),
                    ("enable_xfg_audit_mode", 0x10),
                ],
            );
            let signature_policy_cig = mitigation_from_result(
                query_policy::<PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY>(
                    process,
                    ProcessSignaturePolicy,
                ),
                "GetProcessMitigationPolicy(signature/CIG)",
                |policy| policy.Anonymous.Flags,
                0x27,
                &[
                    ("microsoft_signed_only", 0x1),
                    ("store_signed_only", 0x2),
                    ("mitigation_opt_in", 0x4),
                    ("audit_microsoft_signed_only", 0x8),
                    ("audit_store_signed_only", 0x10),
                    ("enforce_module_dependency_signing", 0x20),
                ],
            );
            let image_load = mitigation_from_result(
                query_policy::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(
                    process,
                    ProcessImageLoadPolicy,
                ),
                "GetProcessMitigationPolicy(image load)",
                |policy| policy.Anonymous.Flags,
                0x7,
                &[
                    ("no_remote_images", 0x1),
                    ("no_low_mandatory_label_images", 0x2),
                    ("prefer_system32_images", 0x4),
                    ("audit_no_remote_images", 0x8),
                    ("audit_no_low_mandatory_label_images", 0x10),
                ],
            );
            let user_shadow_stack = mitigation_from_result(
                query_policy::<PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY>(
                    process,
                    ProcessUserShadowStackPolicy,
                ),
                "GetProcessMitigationPolicy(user shadow stack)",
                |policy| policy.Anonymous.Flags,
                0x1,
                &[
                    ("enable_user_shadow_stack", 0x1),
                    ("audit_user_shadow_stack", 0x2),
                    ("set_context_ip_validation", 0x4),
                    ("audit_set_context_ip_validation", 0x8),
                    ("enable_user_shadow_stack_strict_mode", 0x10),
                    ("block_non_cet_binaries", 0x20),
                    ("block_non_cet_binaries_non_ehcont", 0x40),
                    ("audit_block_non_cet_binaries", 0x80),
                    ("cet_dynamic_apis_out_of_proc_only", 0x100),
                    ("set_context_ip_validation_relaxed_mode", 0x200),
                ],
            );

            MitigationPosture {
                dep,
                aslr,
                dynamic_code,
                strict_handle_check,
                extension_point_disable,
                control_flow_guard,
                signature_policy_cig,
                image_load,
                user_shadow_stack,
            }
        }
    }

    fn query_protection_level(process: HANDLE) -> Evidence<ProtectionLevel> {
        let mut information = PROCESS_PROTECTION_LEVEL_INFORMATION::default();
        // SAFETY: `information` is the correctly sized writable output structure.
        let succeeded = unsafe {
            GetProcessInformation(
                process,
                ProcessProtectionLevelInfo,
                &mut information as *mut PROCESS_PROTECTION_LEVEL_INFORMATION as *mut c_void,
                size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
            )
        };
        if succeeded == 0 {
            // Invalid parameter means this information class is unavailable on the OS.
            // SAFETY: GetLastError has no preconditions.
            return WinFailure::policy(unsafe { GetLastError() })
                .evidence("GetProcessInformation(ProcessProtectionLevelInfo)");
        }

        let raw = information.ProtectionLevel;
        let (name, is_protected, is_ppl) = match raw {
            PROTECTION_LEVEL_NONE => ("none", Some(false), Some(false)),
            PROTECTION_LEVEL_WINTCB_LIGHT => ("WinTcb light", Some(true), Some(true)),
            PROTECTION_LEVEL_WINDOWS => ("Windows", Some(true), Some(false)),
            PROTECTION_LEVEL_WINDOWS_LIGHT => ("Windows light", Some(true), Some(true)),
            PROTECTION_LEVEL_ANTIMALWARE_LIGHT => ("antimalware light", Some(true), Some(true)),
            PROTECTION_LEVEL_LSA_LIGHT => ("LSA light", Some(true), Some(true)),
            PROTECTION_LEVEL_WINTCB => ("WinTcb", Some(true), Some(false)),
            PROTECTION_LEVEL_CODEGEN_LIGHT => ("code generation light", Some(true), Some(true)),
            PROTECTION_LEVEL_AUTHENTICODE => ("Authenticode", Some(true), Some(false)),
            PROTECTION_LEVEL_PPL_APP => ("PPL app", Some(true), Some(true)),
            _ => ("unknown", None, None),
        };
        let level = ProtectionLevel {
            raw_level: raw,
            name: name.to_owned(),
            is_protected,
            is_ppl,
        };
        match is_protected {
            Some(enabled) => Evidence::boolean(enabled, level),
            None => Evidence::available(level),
        }
    }

    fn query_debugger(process: HANDLE) -> Evidence<bool> {
        let mut present = 0;
        // SAFETY: `present` is a valid writable BOOL.
        if unsafe { CheckRemoteDebuggerPresent(process, &mut present) } == 0 {
            // SAFETY: GetLastError has no preconditions.
            return WinFailure::new(unsafe { GetLastError() })
                .evidence("CheckRemoteDebuggerPresent");
        }
        Evidence::boolean(present != 0, present != 0)
    }

    fn query_modules(pid: u32) -> Evidence<ModuleInventory> {
        let snapshot = match create_snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
            Ok(snapshot) => snapshot,
            Err(error) => return error.evidence("CreateToolhelp32Snapshot(modules)"),
        };
        let mut entry = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        // SAFETY: `entry` has the documented size and remains writable.
        if unsafe { Module32FirstW(snapshot.raw(), &mut entry) } == 0 {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_FILES_CODE {
                return Evidence::available(ModuleInventory {
                    count: 0,
                    paths: Vec::new(),
                });
            }
            return WinFailure::new(code).evidence("Module32FirstW");
        }

        let mut paths = Vec::new();
        loop {
            paths.push(wide_string(&entry.szExePath));
            entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
            // SAFETY: `entry` has the documented size and remains writable.
            if unsafe { Module32NextW(snapshot.raw(), &mut entry) } == 0 {
                // SAFETY: GetLastError has no preconditions.
                let code = unsafe { GetLastError() };
                if code == ERROR_NO_MORE_FILES_CODE {
                    break;
                }
                return WinFailure::new(code).evidence("Module32NextW");
            }
        }
        let count = paths.len().min(u32::MAX as usize) as u32;
        Evidence::available(ModuleInventory { count, paths })
    }

    fn query_memory(process: HANDLE) -> Evidence<MemoryRegionSummary> {
        let mut summary = MemoryRegionSummary {
            scanned_region_count: 0,
            executable_private_region_count: 0,
            executable_private_bytes: 0,
            rwx_region_count: 0,
            rwx_bytes: 0,
            private_rwx_region_count: 0,
        };
        let mut address = 0usize;
        loop {
            let mut information = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: this only asks Windows for region metadata. It neither reads
            // nor writes the target's memory contents.
            let bytes = unsafe {
                SetLastError(0);
                VirtualQueryEx(
                    process,
                    address as *const c_void,
                    &mut information,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if bytes == 0 {
                // ERROR_INVALID_PARAMETER is the documented/observed terminal
                // result after the walk reaches beyond the user address space.
                // Any other failure makes the snapshot incomplete and must not
                // be presented as a clean, available summary.
                // SAFETY: GetLastError has no preconditions.
                let code = unsafe { GetLastError() };
                if code == ERROR_INVALID_PARAMETER && summary.scanned_region_count > 0 {
                    break;
                }
                return WinFailure::new(code).evidence(&format!(
                    "VirtualQueryEx after {} regions",
                    summary.scanned_region_count
                ));
            }

            summary.scanned_region_count = summary.scanned_region_count.saturating_add(1);
            let base_protection = information.Protect & 0xff;
            let executable = matches!(
                base_protection,
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            );
            let rwx = matches!(
                base_protection,
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            );
            let committed = information.State == MEM_COMMIT;
            let private = information.Type == MEM_PRIVATE;
            let region_bytes = information.RegionSize.min(u64::MAX as usize) as u64;

            if committed && private && executable {
                summary.executable_private_region_count =
                    summary.executable_private_region_count.saturating_add(1);
                summary.executable_private_bytes = summary
                    .executable_private_bytes
                    .saturating_add(region_bytes);
            }
            if committed && rwx {
                summary.rwx_region_count = summary.rwx_region_count.saturating_add(1);
                summary.rwx_bytes = summary.rwx_bytes.saturating_add(region_bytes);
                if private {
                    summary.private_rwx_region_count =
                        summary.private_rwx_region_count.saturating_add(1);
                }
            }

            let base = information.BaseAddress as usize;
            let Some(next) = base.checked_add(information.RegionSize) else {
                return Evidence::failed(
                    EvidenceState::Error,
                    None,
                    format!(
                        "VirtualQueryEx returned an overflowing region after {} regions",
                        summary.scanned_region_count
                    ),
                );
            };
            if next <= address {
                return Evidence::failed(
                    EvidenceState::Error,
                    None,
                    format!(
                        "VirtualQueryEx returned a non-advancing region after {} regions",
                        summary.scanned_region_count
                    ),
                );
            }
            address = next;
        }
        Evidence::available(summary)
    }

    fn window_affinity(hwnd: HWND) -> Evidence<DisplayAffinity> {
        let mut raw = 0u32;
        // SAFETY: `raw` is a valid writable u32 and hwnd came from EnumWindows.
        unsafe {
            SetLastError(0);
            if GetWindowDisplayAffinity(hwnd, &mut raw) == 0 {
                return WinFailure::new(GetLastError()).evidence("GetWindowDisplayAffinity");
            }
        }
        let kind = match raw {
            WDA_NONE => DisplayAffinityKind::None,
            WDA_MONITOR => DisplayAffinityKind::Monitor,
            WDA_EXCLUDEFROMCAPTURE => DisplayAffinityKind::ExcludeFromCapture,
            _ => DisplayAffinityKind::Unknown,
        };
        let affinity = DisplayAffinity {
            raw_value: raw,
            kind,
        };
        match classify_display_affinity_state(raw, WDA_NONE, WDA_MONITOR, WDA_EXCLUDEFROMCAPTURE) {
            EvidenceState::Enabled => Evidence::boolean(true, affinity),
            EvidenceState::Disabled => Evidence::boolean(false, affinity),
            EvidenceState::Available => Evidence::available(affinity),
            _ => unreachable!("display-affinity classifier returns only known evidence states"),
        }
    }

    struct SelectedWindows {
        pid: u32,
        windows: Vec<WindowPosture>,
    }

    unsafe extern "system" fn selected_window_callback(hwnd: HWND, lparam: LPARAM) -> i32 {
        // SAFETY: EnumWindows invokes this callback synchronously while the
        // context referenced by lparam remains alive and exclusively borrowed.
        let context = unsafe { &mut *(lparam as *mut SelectedWindows) };
        let mut pid = 0u32;
        // SAFETY: `pid` is writable and hwnd is supplied by Windows.
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut pid);
        }
        if pid == context.pid {
            // SAFETY: hwnd is supplied by Windows.
            let visible = unsafe { IsWindowVisible(hwnd) } != 0;
            context.windows.push(WindowPosture {
                hwnd: hwnd as usize as u64,
                title: String::new(),
                visible,
                display_affinity: window_affinity(hwnd),
            });
        }
        1
    }

    fn query_windows(pid: u32) -> Evidence<Vec<WindowPosture>> {
        let mut context = SelectedWindows {
            pid,
            windows: Vec::new(),
        };
        // SAFETY: lparam points to `context` for this synchronous enumeration.
        unsafe {
            SetLastError(0);
            if EnumWindows(
                Some(selected_window_callback),
                &mut context as *mut SelectedWindows as LPARAM,
            ) == 0
            {
                let code = GetLastError();
                if code != 0 {
                    return WinFailure::new(code).evidence("EnumWindows");
                }
            }
        }
        Evidence::available(context.windows)
    }

    fn failed_mitigations(error: WinFailure, operation: &str) -> MitigationPosture {
        let finding = || error.mitigation(operation);
        MitigationPosture {
            dep: finding(),
            aslr: finding(),
            dynamic_code: finding(),
            strict_handle_check: finding(),
            extension_point_disable: finding(),
            control_flow_guard: finding(),
            signature_policy_cig: finding(),
            image_load: finding(),
            user_shadow_stack: finding(),
        }
    }

    pub(super) fn inspect_process(pid: u32) -> ProcessInspection {
        let executable_path = query_image_path(pid);
        let executable_name = process_name(pid, &executable_path);
        let windows = query_windows(pid);
        let modules = query_modules(pid);
        let java_app = if executable_path
            .value
            .as_deref()
            .is_some_and(is_java_runtime_path)
            || has_jvm_module(&modules)
            || executable_path
                .value
                .as_deref()
                .and_then(jpackage_image_target)
                .is_some()
        {
            let cim = query_cim_processes(&format!("ProcessId = {pid}"));
            java_identity(
                &executable_path,
                Some(&modules),
                cim.as_ref()
                    .map(|rows| rows.iter().find(|row| row.process_id == pid)),
            )
        } else {
            None
        };

        match open_process(PROCESS_QUERY_INFORMATION, pid) {
            Ok(process) => ProcessInspection {
                pid,
                executable_name,
                executable_path,
                java_app,
                mitigations: query_mitigations(process.raw()),
                protection_level: query_protection_level(process.raw()),
                remote_debugger_present: query_debugger(process.raw()),
                modules,
                memory: query_memory(process.raw()),
                windows,
            },
            Err(error) => ProcessInspection {
                pid,
                executable_name,
                executable_path,
                java_app,
                mitigations: failed_mitigations(error, "OpenProcess(PROCESS_QUERY_INFORMATION)"),
                protection_level: error.evidence("OpenProcess for protection level"),
                remote_debugger_present: error.evidence("OpenProcess for debugger query"),
                modules,
                memory: error.evidence("OpenProcess for virtual-memory metadata"),
                windows,
            },
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    const MESSAGE: &str = "live process posture inspection is available only on Windows";

    pub(super) fn enumerate_running_processes() -> Evidence<Vec<ProcessSummary>> {
        Evidence::unavailable(MESSAGE)
    }

    pub(super) fn inspect_process(pid: u32) -> ProcessInspection {
        ProcessInspection {
            pid,
            executable_name: Evidence::unavailable(MESSAGE),
            executable_path: Evidence::unavailable(MESSAGE),
            java_app: None,
            mitigations: MitigationPosture::unavailable(MESSAGE),
            protection_level: Evidence::unavailable(MESSAGE),
            remote_debugger_present: Evidence::unavailable(MESSAGE),
            modules: Evidence::unavailable(MESSAGE),
            memory: Evidence::unavailable(MESSAGE),
            windows: Evidence::unavailable(MESSAGE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_launcher_extracts_only_jar_target_from_quoted_command_line() {
        let command_line = r#""C:\Program Files\Java\bin\javaw.exe" -Xmx1g -jar "C:\Apps\My Tool\client.jar" --password secret-value"#;
        let (kind, target) = parse_java_launch_target(command_line);
        assert_eq!(kind, JavaLaunchKind::Jar);
        assert_eq!(target.as_deref(), Some(r"C:\Apps\My Tool\client.jar"));
        assert!(!format!("{target:?}").contains("secret-value"));
    }

    #[test]
    fn java_launcher_skips_classpath_and_module_options() {
        let (kind, target) = parse_java_launch_target(
            r#"java.exe -Dmode=test -cp "C:\libs\first.jar;C:\libs\second.jar" com.example.Main --token secret"#,
        );
        assert_eq!(kind, JavaLaunchKind::MainClass);
        assert_eq!(target.as_deref(), Some("com.example.Main"));
        let (kind, target) = parse_java_launch_target(
            r#"java.exe --module-path "C:\module jars" -m example.module/com.example.Main private-arg"#,
        );
        assert_eq!(kind, JavaLaunchKind::Module);
        assert_eq!(target.as_deref(), Some("example.module/com.example.Main"));
    }

    #[test]
    fn java_argument_file_does_not_guess_a_later_target() {
        let (kind, target) =
            parse_java_launch_target("java.exe @C:\\config\\launch.args secret-argument");
        assert_eq!(kind, JavaLaunchKind::Unknown);
        assert_eq!(target, None);
    }

    #[test]
    fn jpackage_config_uses_application_target_only() {
        let config = "[Application]\napp.runtime=$ROOTDIR\\runtime\napp.mainclass=com.example.Main\napp.classpath=$APPDIR\\app.jar\n\n[ArgOptions]\narguments=secret-argument\n";
        let (kind, target) = parse_jpackage_config(config);
        assert_eq!(kind, JavaLaunchKind::MainClass);
        assert_eq!(target.as_deref(), Some("com.example.Main"));
        assert!(!format!("{target:?}").contains("secret-argument"));
    }

    #[test]
    fn aslr_does_not_treat_disallow_stripped_images_as_randomization() {
        assert_eq!(classify_aslr_state(0x08), EvidenceState::Disabled);
        assert_eq!(classify_aslr_state(0x01), EvidenceState::Enabled);
        assert_eq!(classify_aslr_state(0x02), EvidenceState::Enabled);
        assert_eq!(classify_aslr_state(0x04), EvidenceState::Enabled);
    }

    #[test]
    fn dynamic_code_requires_unweakened_prohibition() {
        assert_eq!(classify_dynamic_code_state(0x00), EvidenceState::Disabled);
        assert_eq!(classify_dynamic_code_state(0x01), EvidenceState::Enabled);
        assert_eq!(classify_dynamic_code_state(0x03), EvidenceState::Available);
        assert_eq!(classify_dynamic_code_state(0x05), EvidenceState::Available);
        assert_eq!(classify_dynamic_code_state(0x07), EvidenceState::Available);
    }

    #[test]
    fn unknown_display_affinity_is_observable_not_enabled() {
        assert_eq!(
            classify_display_affinity_state(0x44, 0x00, 0x01, 0x11),
            EvidenceState::Available
        );
        assert_eq!(
            classify_display_affinity_state(0x00, 0x00, 0x01, 0x11),
            EvidenceState::Disabled
        );
        assert_eq!(
            classify_display_affinity_state(0x11, 0x00, 0x01, 0x11),
            EvidenceState::Enabled
        );
    }
}
