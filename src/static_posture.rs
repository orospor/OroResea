//! Read-only inspection of security-related metadata in Windows PE images.
//!
//! The values reported by this module are build-time declarations and metadata.
//! They do not prove that a mitigation is active for a running process, and they
//! do not prove that process injection is impossible. Runtime posture must be
//! queried from a live process separately.

use goblin::{
    Object,
    pe::{
        PE,
        debug::{
            IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT,
            IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE,
        },
        dll_characteristic::{
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
        },
        load_config::{IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, IMAGE_GUARD_CF_INSTRUMENTED},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
/// Static analysis is intentionally bounded so an accidentally selected disk
/// image or sparse file cannot force an unbounded allocation. Normal Windows
/// executables and DLLs are comfortably below this limit.
const MAX_STATIC_INPUT_BYTES: u64 = 512 * 1024 * 1024;

/// Static, file-level mitigation declarations found in a PE image.
///
/// A `true` value means that the corresponding bit or metadata record exists in
/// the file. It is deliberately not named `*_enabled`: Windows may apply,
/// override, or decline a mitigation when the image is loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticPosture {
    /// Set only by [`analyze_path`].
    pub source_path: Option<PathBuf>,
    pub pe32_plus: bool,
    pub machine: u16,
    pub header: HeaderMitigationPosture,
    pub control_flow_guard: ControlFlowGuardPosture,
    pub cet: CetMetadataPosture,
    pub authenticode: AuthenticodePosture,
    /// Scope reminder suitable for displaying beside the result.
    pub scope_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderMitigationPosture {
    pub dll_characteristics: u16,
    /// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` is present.
    pub dynamic_base_declared: bool,
    /// The COFF header does not declare relocations stripped.
    pub relocations_not_stripped: bool,
    /// A non-empty base-relocation data directory is declared in the optional
    /// header. This is stronger evidence than the COFF flag alone.
    pub base_relocation_directory_present: bool,
    /// Raw RVA from the base-relocation data-directory entry, when declared.
    pub base_relocation_directory_rva: Option<u32>,
    /// Raw size from the base-relocation data-directory entry, when declared.
    pub base_relocation_directory_size: Option<u32>,
    /// The image declares dynamic-base support, does not strip relocations, and
    /// has a non-empty base-relocation directory. This is static loader
    /// readiness, not proof that a live process was randomized.
    pub aslr_relocation_ready: bool,
    /// `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` is present.
    pub high_entropy_va_declared: bool,
    /// High-entropy VA is meaningful for this PE32+ image format.
    pub high_entropy_va_applicable: bool,
    /// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` is present.
    pub nx_compat_declared: bool,
    /// `IMAGE_DLLCHARACTERISTICS_GUARD_CF` is present.
    pub guard_cf_declared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowGuardPosture {
    /// Copy of the optional-header Guard CF bit.
    pub dll_characteristics_guard_cf: bool,
    pub load_config_present: bool,
    /// Raw `GuardFlags`, or `None` when that field is absent from the image's
    /// load-config structure.
    pub load_config_guard_flags: Option<u32>,
    pub load_config_cf_instrumented: Option<bool>,
    pub load_config_function_table_flag: Option<bool>,
    pub guard_function_table_pointer_present: Option<bool>,
    pub guard_function_count: Option<u64>,
    /// Whether the Guard Function Table flag agrees with the table pointer and
    /// count, when enough load-config evidence is available to decide.
    pub guard_function_table_metadata_consistent: Option<bool>,
    /// `Some(true)` means the optional-header Guard CF bit and load-config
    /// instrumentation flag have the same value. Agreement is not the same as
    /// confirmation: both values can agree that instrumentation is absent.
    /// `None` means the load-config flag was unavailable.
    pub header_and_load_config_agree: Option<bool>,
    /// Static CFG instrumentation is confirmed only when both independent CFG
    /// declarations are present and any declared Guard Function Table is
    /// internally coherent. This still does not prove live enforcement.
    pub cfg_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CetMetadataPosture {
    /// Extended DLL-characteristics metadata was parsed from the PE debug
    /// directory. Absence leaves the following fields `None` (unknown).
    pub metadata_present: bool,
    pub extended_dll_characteristics: Option<u32>,
    /// The image declares `CET_COMPAT`; this is compatibility metadata, not a
    /// live hardware-enforcement measurement.
    pub cet_compat_declared: Option<bool>,
    pub cet_strict_mode_declared: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticodeStatus {
    NotPresent,
    /// An embedded certificate table exists, but trust was not evaluated (for
    /// example, because only bytes were supplied or the host is not Windows).
    PresentUnverified,
    /// Windows' generic Authenticode trust provider accepted the file.
    Valid,
    /// Windows evaluated the signature but rejected its signature/chain/trust.
    TrustFailure,
    /// Trust evaluation could not be completed for another reason.
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticodePosture {
    /// Whether the PE optional header declares a non-empty certificate table.
    pub embedded_certificate_table_present: bool,
    /// Number of certificate entries successfully parsed by Goblin.
    pub parsed_certificate_count: usize,
    pub status: AuthenticodeStatus,
    /// Signed WinVerifyTrust status on Windows; `0` means success.
    pub platform_status_code: Option<i32>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticPostureErrorKind {
    Io,
    InputTooLarge,
    NotPortableExecutable,
    MissingOptionalHeader,
    MalformedPortableExecutable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticPostureError {
    pub kind: StaticPostureErrorKind,
    pub message: String,
}

impl StaticPostureError {
    fn new(kind: StaticPostureErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for StaticPostureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StaticPostureError {}

/// Reads and analyzes a PE without modifying or loading it.
///
/// On Windows, an embedded Authenticode signature is submitted to
/// `WinVerifyTrust`. The check is cache-only and does not fetch revocation data
/// from the network, so the detail field explicitly records that limitation.
pub fn analyze_path(path: &Path) -> Result<StaticPosture, StaticPostureError> {
    let metadata = fs::metadata(path).map_err(|error| {
        StaticPostureError::new(
            StaticPostureErrorKind::Io,
            format!("Could not inspect {}: {error}", path.display()),
        )
    })?;
    validate_input_size(metadata.len(), path)?;

    let file = File::open(path).map_err(|error| {
        StaticPostureError::new(
            StaticPostureErrorKind::Io,
            format!("Could not open {}: {error}", path.display()),
        )
    })?;
    let initial_capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(initial_capacity);
    // Bound the actual read as well as the metadata check. This closes the
    // allocation race if a file grows after its metadata was queried.
    file.take(MAX_STATIC_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            StaticPostureError::new(
                StaticPostureErrorKind::Io,
                format!("Could not read {}: {error}", path.display()),
            )
        })?;
    validate_input_size(bytes.len() as u64, path)?;

    analyze_impl(&bytes, Some(path))
}

fn validate_input_size(size: u64, path: &Path) -> Result<(), StaticPostureError> {
    if size > MAX_STATIC_INPUT_BYTES {
        return Err(StaticPostureError::new(
            StaticPostureErrorKind::InputTooLarge,
            format!(
                "{} is {} bytes; static PE analysis is limited to {} bytes",
                path.display(),
                size,
                MAX_STATIC_INPUT_BYTES
            ),
        ));
    }
    Ok(())
}

/// Analyzes in-memory PE bytes without writing or loading them.
///
/// Trust cannot be established for detached bytes, so a present certificate is
/// reported as [`AuthenticodeStatus::PresentUnverified`]. Use [`analyze_path`]
/// on Windows when platform trust validation is required.
#[cfg(test)]
pub fn analyze_bytes(bytes: &[u8]) -> Result<StaticPosture, StaticPostureError> {
    analyze_impl(bytes, None)
}

fn analyze_impl(
    bytes: &[u8],
    source_path: Option<&Path>,
) -> Result<StaticPosture, StaticPostureError> {
    let pe = match Object::parse(bytes) {
        Ok(Object::PE(pe)) => pe,
        Ok(_) => {
            return Err(StaticPostureError::new(
                StaticPostureErrorKind::NotPortableExecutable,
                "Input is not a Windows Portable Executable image",
            ));
        }
        Err(error) => {
            return Err(StaticPostureError::new(
                StaticPostureErrorKind::MalformedPortableExecutable,
                format!("PE parsing failed: {error}"),
            ));
        }
    };

    posture_from_pe(&pe, source_path)
}

fn posture_from_pe(
    pe: &PE<'_>,
    source_path: Option<&Path>,
) -> Result<StaticPosture, StaticPostureError> {
    let optional_header = pe.header.optional_header.as_ref().ok_or_else(|| {
        StaticPostureError::new(
            StaticPostureErrorKind::MissingOptionalHeader,
            "PE image has no optional header, so mitigation flags are unavailable",
        )
    })?;

    let dll_characteristics = optional_header.windows_fields.dll_characteristics;
    let base_relocation_directory = optional_header
        .data_directories
        .get_base_relocation_table()
        .map(|directory| (directory.virtual_address, directory.size));
    let header = parse_header_mitigations(
        dll_characteristics,
        pe.header.coff_header.characteristics,
        pe.is_64,
        base_relocation_directory,
    );
    let control_flow_guard = parse_cfg_posture(pe, header.guard_cf_declared);
    let cet = parse_cet_posture(pe);
    let certificate_table_present = optional_header
        .data_directories
        .get_certificate_table()
        .is_some_and(|directory| directory.virtual_address != 0 && directory.size >= 8);
    let authenticode = authenticode_posture(
        source_path,
        certificate_table_present,
        pe.certificates.len(),
    );

    Ok(StaticPosture {
        source_path: source_path.map(Path::to_path_buf),
        pe32_plus: pe.is_64,
        machine: pe.header.coff_header.machine,
        header,
        control_flow_guard,
        cet,
        authenticode,
        scope_note: "Static PE declarations only; this result does not confirm live process mitigations or immunity to injection."
            .to_owned(),
    })
}

fn parse_header_mitigations(
    dll_characteristics: u16,
    coff_characteristics: u16,
    pe32_plus: bool,
    base_relocation_directory: Option<(u32, u32)>,
) -> HeaderMitigationPosture {
    let dynamic_base_declared =
        has_u16_flag(dll_characteristics, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
    let relocations_not_stripped = !has_u16_flag(coff_characteristics, IMAGE_FILE_RELOCS_STRIPPED);
    let (base_relocation_directory_rva, base_relocation_directory_size) =
        match base_relocation_directory {
            Some((rva, size)) => (Some(rva), Some(size)),
            None => (None, None),
        };
    let base_relocation_directory_present =
        base_relocation_directory.is_some_and(|(rva, size)| rva != 0 && size != 0);

    HeaderMitigationPosture {
        dll_characteristics,
        dynamic_base_declared,
        relocations_not_stripped,
        base_relocation_directory_present,
        base_relocation_directory_rva,
        base_relocation_directory_size,
        aslr_relocation_ready: dynamic_base_declared
            && relocations_not_stripped
            && base_relocation_directory_present,
        high_entropy_va_declared: has_u16_flag(
            dll_characteristics,
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
        ),
        high_entropy_va_applicable: pe32_plus,
        nx_compat_declared: has_u16_flag(dll_characteristics, IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
        guard_cf_declared: has_u16_flag(dll_characteristics, IMAGE_DLLCHARACTERISTICS_GUARD_CF),
    }
}

fn parse_cfg_posture(pe: &PE<'_>, header_guard_cf: bool) -> ControlFlowGuardPosture {
    let load_config = pe.load_config_data.as_ref().map(|data| &data.directory);
    let guard_flags = load_config.and_then(|directory| directory.guard_flags);
    let cf_instrumented = guard_flags.map(|flags| has_u32_flag(flags, IMAGE_GUARD_CF_INSTRUMENTED));
    let function_table_flag =
        guard_flags.map(|flags| has_u32_flag(flags, IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT));
    let function_table_pointer_present = load_config.and_then(|directory| {
        directory
            .guard_cf_function_table
            .map(|pointer| pointer != 0)
    });
    let function_count = load_config.and_then(|directory| directory.guard_cf_function_count);
    let table_consistency = guard_table_consistency(
        function_table_flag,
        function_table_pointer_present,
        function_count,
    );
    let header_and_load_config_agree =
        cf_instrumented.map(|instrumented| header_guard_cf == instrumented);
    let cfg_confirmed = cfg_is_confirmed(header_guard_cf, cf_instrumented, table_consistency);

    ControlFlowGuardPosture {
        dll_characteristics_guard_cf: header_guard_cf,
        load_config_present: load_config.is_some(),
        load_config_guard_flags: guard_flags,
        load_config_cf_instrumented: cf_instrumented,
        load_config_function_table_flag: function_table_flag,
        guard_function_table_pointer_present: function_table_pointer_present,
        guard_function_count: function_count,
        guard_function_table_metadata_consistent: table_consistency,
        header_and_load_config_agree,
        cfg_confirmed,
    }
}

fn guard_table_consistency(
    table_flag: Option<bool>,
    pointer_present: Option<bool>,
    function_count: Option<u64>,
) -> Option<bool> {
    let table_flag = table_flag?;

    if table_flag {
        // A declared Guard Function Table needs both a usable pointer and at
        // least one entry. Missing optional fields are treated as insufficient
        // evidence, not silently converted into zero.
        return match (pointer_present, function_count) {
            (Some(pointer_present), Some(function_count)) => {
                Some(pointer_present && function_count > 0)
            }
            _ => None,
        };
    }

    // With no table declared, explicit non-zero table metadata conflicts with
    // GuardFlags. Absent fields are normal for older/smaller load-config forms.
    let pointer_conflicts = pointer_present == Some(true);
    let count_conflicts = function_count.is_some_and(|count| count > 0);
    Some(!pointer_conflicts && !count_conflicts)
}

fn cfg_is_confirmed(
    header_guard_cf: bool,
    load_config_instrumented: Option<bool>,
    guard_table_consistent: Option<bool>,
) -> bool {
    header_guard_cf
        && load_config_instrumented == Some(true)
        && guard_table_consistent == Some(true)
}

fn parse_cet_posture(pe: &PE<'_>) -> CetMetadataPosture {
    let characteristics = pe
        .debug_data
        .as_ref()
        .and_then(|debug| debug.ex_dll_characteristics_info)
        .map(|info| info.characteristics_ex);

    CetMetadataPosture {
        metadata_present: characteristics.is_some(),
        extended_dll_characteristics: characteristics,
        cet_compat_declared: characteristics
            .map(|flags| has_u32_flag(flags, IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT)),
        cet_strict_mode_declared: characteristics
            .map(|flags| has_u32_flag(flags, IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE)),
    }
}

fn authenticode_posture(
    source_path: Option<&Path>,
    certificate_table_present: bool,
    parsed_certificate_count: usize,
) -> AuthenticodePosture {
    if !certificate_table_present {
        return AuthenticodePosture {
            embedded_certificate_table_present: false,
            parsed_certificate_count,
            status: AuthenticodeStatus::NotPresent,
            platform_status_code: None,
            detail: "No embedded PE certificate table was declared. Catalog signatures are outside this check, so this is not proof that Windows considers the file unsigned."
                .to_owned(),
        };
    }

    let Some(path) = source_path else {
        return present_unverified(
            parsed_certificate_count,
            "An embedded certificate table is present, but byte-only analysis cannot establish file trust.",
        );
    };

    #[cfg(target_os = "windows")]
    {
        verify_authenticode_windows(path, parsed_certificate_count)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        present_unverified(
            parsed_certificate_count,
            "An embedded certificate table is present; platform trust validation is available only on Windows.",
        )
    }
}

fn present_unverified(parsed_certificate_count: usize, detail: &str) -> AuthenticodePosture {
    AuthenticodePosture {
        embedded_certificate_table_present: true,
        parsed_certificate_count,
        status: AuthenticodeStatus::PresentUnverified,
        platform_status_code: None,
        detail: detail.to_owned(),
    }
}

fn has_u16_flag(value: u16, flag: u16) -> bool {
    value & flag == flag
}

fn has_u32_flag(value: u32, flag: u32) -> bool {
    value & flag == flag
}

#[cfg(target_os = "windows")]
fn verify_authenticode_windows(
    path: &Path,
    parsed_certificate_count: usize,
) -> AuthenticodePosture {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr};

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct WintrustFileInfo {
        cb_struct: u32,
        file_path: *const u16,
        file_handle: *mut c_void,
        known_subject: *const Guid,
    }

    #[repr(C)]
    union WintrustDataChoice {
        file: *mut WintrustFileInfo,
    }

    #[repr(C)]
    struct WintrustData {
        cb_struct: u32,
        policy_callback_data: *mut c_void,
        sip_client_data: *mut c_void,
        ui_choice: u32,
        revocation_checks: u32,
        union_choice: u32,
        choice: WintrustDataChoice,
        state_action: u32,
        state_data: *mut c_void,
        url_reference: *const u16,
        provider_flags: u32,
        ui_context: u32,
        // Present in the current WINTRUST_DATA ABI. It must remain the trailing
        // field even though this scanner does not request secondary signatures.
        signature_settings: *mut c_void,
    }

    #[link(name = "wintrust")]
    unsafe extern "system" {
        fn WinVerifyTrust(
            window: *mut c_void,
            action: *const Guid,
            trust_data: *mut WintrustData,
        ) -> i32;
    }

    const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
        data1: 0x00AA_C56B,
        data2: 0xCD44,
        data3: 0x11D0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };
    const WTD_UI_NONE: u32 = 2;
    const WTD_REVOKE_NONE: u32 = 0;
    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_STATEACTION_IGNORE: u32 = 0;
    const WTD_REVOCATION_CHECK_NONE: u32 = 0x10;
    const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x1000;

    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide_path.contains(&0) {
        return AuthenticodePosture {
            embedded_certificate_table_present: true,
            parsed_certificate_count,
            status: AuthenticodeStatus::Error,
            platform_status_code: None,
            detail:
                "The file path contains an embedded NUL and cannot be passed to WinVerifyTrust."
                    .to_owned(),
        };
    }
    wide_path.push(0);

    let mut file_info = WintrustFileInfo {
        cb_struct: std::mem::size_of::<WintrustFileInfo>() as u32,
        file_path: wide_path.as_ptr(),
        file_handle: ptr::null_mut(),
        known_subject: ptr::null(),
    };
    let mut trust_data = WintrustData {
        cb_struct: std::mem::size_of::<WintrustData>() as u32,
        policy_callback_data: ptr::null_mut(),
        sip_client_data: ptr::null_mut(),
        ui_choice: WTD_UI_NONE,
        revocation_checks: WTD_REVOKE_NONE,
        union_choice: WTD_CHOICE_FILE,
        choice: WintrustDataChoice {
            file: &mut file_info,
        },
        state_action: WTD_STATEACTION_IGNORE,
        state_data: ptr::null_mut(),
        url_reference: ptr::null(),
        provider_flags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ui_context: 0,
        signature_settings: ptr::null_mut(),
    };

    // SAFETY: The C-layout structures above match WINTRUST_FILE_INFO and
    // WINTRUST_DATA. All pointers remain valid for the duration of this call,
    // and WinVerifyTrust treats the supplied file as read-only input.
    let status_code = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut trust_data,
        )
    };

    let status = classify_winverifytrust_status(status_code);
    let detail = match status {
        AuthenticodeStatus::Valid => "WinVerifyTrust accepted the embedded Authenticode signature using cache-only trust evaluation; online revocation retrieval was not performed."
            .to_owned(),
        AuthenticodeStatus::TrustFailure => format!(
            "WinVerifyTrust completed evaluation and rejected the signature or trust chain (status 0x{:08X}); online revocation retrieval was not performed.",
            status_code as u32
        ),
        AuthenticodeStatus::Error if is_revocation_indeterminate(status_code) => format!(
            "WinVerifyTrust could not determine trust because revocation evidence was unavailable during cache-only evaluation (status 0x{:08X}).",
            status_code as u32
        ),
        AuthenticodeStatus::Error if is_provider_or_subject_form_error(status_code) => format!(
            "WinVerifyTrust could not evaluate this subject with the requested provider/action (status 0x{:08X}).",
            status_code as u32
        ),
        _ => format!(
            "WinVerifyTrust could not complete trust evaluation (status 0x{:08X}).",
            status_code as u32
        ),
    };

    AuthenticodePosture {
        embedded_certificate_table_present: true,
        parsed_certificate_count,
        status,
        platform_status_code: Some(status_code),
        detail,
    }
}

fn classify_winverifytrust_status(status: i32) -> AuthenticodeStatus {
    if status == 0 {
        return AuthenticodeStatus::Valid;
    }

    if is_provider_or_subject_form_error(status) || is_revocation_indeterminate(status) {
        return AuthenticodeStatus::Error;
    }

    if matches!(
        status as u32,
        // Signature, digest, countersigner, and policy trust failures.
        0x8009_6002..=0x8009_6005
            | 0x8009_6010
            | 0x8009_6019
            | 0x8009_601E
            // TRUST_E_SUBJECT_NOT_TRUSTED (the preceding provider/action/form
            // codes are indeterminate errors, handled above).
            | 0x800B_0004
            // TRUST_E_NOSIGNATURE.
            | 0x800B_0100
            // Certificate/trust rejection codes. CERT_E_REVOCATION_FAILURE is
            // excluded below because it means evaluation was indeterminate.
            | 0x800B_0101..=0x800B_010D
            | 0x800B_010F..=0x800B_0114
            // CRYPT_E_REVOKED and policy security-settings rejection.
            | 0x8009_2010
            | 0x8009_2026
    ) {
        AuthenticodeStatus::TrustFailure
    } else {
        AuthenticodeStatus::Error
    }
}

fn is_provider_or_subject_form_error(status: i32) -> bool {
    matches!(
        status as u32,
        // TRUST_E_PROVIDER_UNKNOWN, TRUST_E_ACTION_UNKNOWN,
        // TRUST_E_SUBJECT_FORM_UNKNOWN, and TRUST_E_SYSTEM_ERROR.
        0x800B_0001..=0x800B_0003 | 0x8009_6001
    )
}

fn is_revocation_indeterminate(status: i32) -> bool {
    matches!(
        status as u32,
        // CRYPT_E_NO_REVOCATION_CHECK, CRYPT_E_REVOCATION_OFFLINE, and
        // CERT_E_REVOCATION_FAILURE.
        0x8009_2012 | 0x8009_2013 | 0x800B_010E
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_requested_dll_characteristic() {
        let all_requested = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
            | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            | IMAGE_DLLCHARACTERISTICS_GUARD_CF;

        let posture = parse_header_mitigations(all_requested, 0, true, Some((0x4000, 0x280)));

        assert_eq!(posture.dll_characteristics, all_requested);
        assert!(posture.dynamic_base_declared);
        assert!(posture.relocations_not_stripped);
        assert!(posture.base_relocation_directory_present);
        assert_eq!(posture.base_relocation_directory_rva, Some(0x4000));
        assert_eq!(posture.base_relocation_directory_size, Some(0x280));
        assert!(posture.aslr_relocation_ready);
        assert!(posture.high_entropy_va_declared);
        assert!(posture.high_entropy_va_applicable);
        assert!(posture.nx_compat_declared);
        assert!(posture.guard_cf_declared);
    }

    #[test]
    fn absent_flags_remain_false() {
        let posture = parse_header_mitigations(0, IMAGE_FILE_RELOCS_STRIPPED, false, None);

        assert!(!posture.dynamic_base_declared);
        assert!(!posture.relocations_not_stripped);
        assert!(!posture.base_relocation_directory_present);
        assert_eq!(posture.base_relocation_directory_rva, None);
        assert_eq!(posture.base_relocation_directory_size, None);
        assert!(!posture.aslr_relocation_ready);
        assert!(!posture.high_entropy_va_declared);
        assert!(!posture.high_entropy_va_applicable);
        assert!(!posture.nx_compat_declared);
        assert!(!posture.guard_cf_declared);
    }

    #[test]
    fn unrelated_bits_do_not_trigger_mitigations() {
        let posture = parse_header_mitigations(0x8000, 0, true, None);

        assert!(!posture.dynamic_base_declared);
        assert!(!posture.high_entropy_va_declared);
        assert!(!posture.nx_compat_declared);
        assert!(!posture.guard_cf_declared);
    }

    #[test]
    fn dynamic_base_without_nonempty_relocation_directory_is_not_aslr_ready() {
        let zero_sized = parse_header_mitigations(
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
            0,
            true,
            Some((0x4000, 0)),
        );
        assert!(!zero_sized.base_relocation_directory_present);
        assert_eq!(zero_sized.base_relocation_directory_size, Some(0));
        assert!(!zero_sized.aslr_relocation_ready);

        let stripped = parse_header_mitigations(
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
            IMAGE_FILE_RELOCS_STRIPPED,
            true,
            Some((0x4000, 0x280)),
        );
        assert!(stripped.base_relocation_directory_present);
        assert!(!stripped.aslr_relocation_ready);
    }

    #[test]
    fn guard_flag_parser_requires_the_complete_mask() {
        assert!(has_u32_flag(
            IMAGE_GUARD_CF_INSTRUMENTED | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
            IMAGE_GUARD_CF_INSTRUMENTED,
        ));
        assert!(has_u32_flag(
            IMAGE_GUARD_CF_INSTRUMENTED | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
            IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
        ));
        assert!(!has_u32_flag(0, IMAGE_GUARD_CF_INSTRUMENTED));
    }

    #[test]
    fn cfg_agreement_is_distinct_from_confirmation() {
        // Both sources agreeing that CFG is absent is agreement, not a
        // positive confirmation of instrumentation.
        let both_absent_agree = Some(false).map(|instrumented| !instrumented);
        assert_eq!(both_absent_agree, Some(true));
        assert!(!cfg_is_confirmed(false, Some(false), Some(true)));

        assert!(cfg_is_confirmed(true, Some(true), Some(true)));
        assert!(!cfg_is_confirmed(true, Some(true), Some(false)));
        assert!(!cfg_is_confirmed(true, Some(true), None));
        assert!(!cfg_is_confirmed(true, None, Some(true)));
    }

    #[test]
    fn cfg_guard_table_metadata_requires_a_real_declared_table() {
        assert_eq!(
            guard_table_consistency(Some(true), Some(true), Some(7)),
            Some(true)
        );
        assert_eq!(
            guard_table_consistency(Some(true), Some(false), Some(7)),
            Some(false)
        );
        assert_eq!(
            guard_table_consistency(Some(true), Some(true), Some(0)),
            Some(false)
        );
        assert_eq!(
            guard_table_consistency(Some(false), Some(false), Some(0)),
            Some(true)
        );
        assert_eq!(guard_table_consistency(Some(true), None, Some(7)), None);
    }

    #[test]
    fn static_input_size_limit_has_a_distinct_error_kind() {
        validate_input_size(MAX_STATIC_INPUT_BYTES, Path::new("at-limit.exe"))
            .expect("the configured limit is accepted");
        let error = validate_input_size(MAX_STATIC_INPUT_BYTES + 1, Path::new("too-large.exe"))
            .expect_err("an oversized input must be rejected before parsing");
        assert_eq!(error.kind, StaticPostureErrorKind::InputTooLarge);
    }

    #[test]
    fn winverifytrust_indeterminate_codes_are_not_trust_failures() {
        assert_eq!(classify_winverifytrust_status(0), AuthenticodeStatus::Valid);
        assert_eq!(
            classify_winverifytrust_status(0x800B_0001u32 as i32),
            AuthenticodeStatus::Error
        );
        assert_eq!(
            classify_winverifytrust_status(0x800B_0002u32 as i32),
            AuthenticodeStatus::Error
        );
        assert_eq!(
            classify_winverifytrust_status(0x800B_0003u32 as i32),
            AuthenticodeStatus::Error
        );
        assert_eq!(
            classify_winverifytrust_status(0x8009_2012u32 as i32),
            AuthenticodeStatus::Error
        );
        assert_eq!(
            classify_winverifytrust_status(0x8009_2013u32 as i32),
            AuthenticodeStatus::Error
        );
        assert_eq!(
            classify_winverifytrust_status(0x800B_010Eu32 as i32),
            AuthenticodeStatus::Error
        );
        assert_eq!(
            classify_winverifytrust_status(0x8009_6010u32 as i32),
            AuthenticodeStatus::TrustFailure
        );
        assert_eq!(
            classify_winverifytrust_status(0x800B_0109u32 as i32),
            AuthenticodeStatus::TrustFailure
        );
    }

    #[test]
    fn authenticode_status_serializes_to_honest_wire_names() {
        assert_eq!(
            serde_json::to_string(&AuthenticodeStatus::PresentUnverified).unwrap(),
            "\"present_unverified\""
        );
        assert_eq!(
            serde_json::to_string(&AuthenticodeStatus::TrustFailure).unwrap(),
            "\"trust_failure\""
        );
    }

    #[test]
    fn byte_analysis_rejects_non_pe_input() {
        let error = analyze_bytes(b"not a portable executable")
            .expect_err("arbitrary bytes must not be accepted as a PE");
        assert!(matches!(
            error.kind,
            StaticPostureErrorKind::MalformedPortableExecutable
                | StaticPostureErrorKind::NotPortableExecutable
        ));
    }
}
