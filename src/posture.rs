use crate::{
    live_posture::{
        self, DisplayAffinityKind, EvidenceState, MemoryRegionSummary, MitigationFinding,
        ProcessInspection, ProcessSummary,
    },
    model::{
        AuditScope, PostureAssessment, PostureCheck, PostureTarget, PostureVerdict, ProtectionKind,
    },
    static_posture::{self, AuthenticodeStatus, StaticPosture, StaticPostureError},
};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

pub enum PostureMessage {
    Finished(PostureAssessment),
}

pub fn enumerate_processes(visible_only: bool) -> Result<Vec<ProcessSummary>, String> {
    if !live_posture::is_supported() {
        return Err("Live process posture inspection is available only on Windows.".to_owned());
    }
    let evidence = if visible_only {
        live_posture::enumerate_user_visible_processes()
    } else {
        live_posture::enumerate_running_processes()
    };
    match evidence.value {
        Some(mut processes) => {
            processes.sort_by(|left, right| {
                left.executable_name
                    .to_ascii_lowercase()
                    .cmp(&right.executable_name.to_ascii_lowercase())
                    .then_with(|| left.pid.cmp(&right.pid))
            });
            Ok(processes)
        }
        None => Err(evidence
            .message
            .unwrap_or_else(|| "Windows did not return a process inventory.".to_owned())),
    }
}

pub fn spawn_file_assessment(path: PathBuf) -> Receiver<PostureMessage> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(PostureMessage::Finished(assess_file(&path)));
    });
    rx
}

pub fn spawn_process_assessment(pid: u32) -> Receiver<PostureMessage> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(PostureMessage::Finished(assess_process(pid)));
    });
    rx
}

pub fn assess_file(path: &Path) -> PostureAssessment {
    let mut checks = Vec::new();
    let mut limitations = base_limitations();
    match static_posture::analyze_path(path) {
        Ok(posture) => append_static_checks(&mut checks, &posture),
        Err(error) => append_static_error_checks(&mut checks, &error),
    }
    append_not_running_checks(&mut checks);
    append_system_gaps(&mut checks);
    limitations.push(
        "No target was executed. Effective process policies and runtime WDA require a live-process snapshot."
            .to_owned(),
    );

    PostureAssessment {
        target: PostureTarget {
            path: Some(path.to_owned()),
            pid: None,
            process_name: path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned),
        },
        captured_unix_seconds: captured_time(),
        checks,
        limitations,
    }
}

pub fn assess_process(pid: u32) -> PostureAssessment {
    let inspection = live_posture::inspect_process(pid);
    let path = inspection
        .executable_path
        .value
        .as_deref()
        .map(PathBuf::from);
    let process_name = inspection.executable_name.value.clone();
    let mut checks = Vec::new();
    let mut limitations = base_limitations();

    if let Some(path) = &path {
        match static_posture::analyze_path(path) {
            Ok(posture) => append_static_checks(&mut checks, &posture),
            Err(error) => append_static_error_checks(&mut checks, &error),
        }
    } else {
        let detail = inspection
            .executable_path
            .message
            .as_deref()
            .unwrap_or("The executable path was unavailable.");
        append_unavailable_static_checks(&mut checks, detail);
    }

    append_live_checks(&mut checks, &inspection);
    append_system_gaps(&mut checks);
    limitations.push(
        "This is a point-in-time snapshot. A later policy change, module load, or injection attempt is not covered."
            .to_owned(),
    );
    limitations.push(
        "Loaded-module paths are inventoried, but every module's signer is not trust-validated in this snapshot."
            .to_owned(),
    );
    limitations.push(
        "Live checks are sequential rather than atomic. The process can change or exit during collection, and the current on-disk executable may differ from the image already mapped in memory."
            .to_owned(),
    );
    limitations.push(
        "A PID can be reused after a process exits; confirm the displayed name and executable path before relying on a snapshot."
            .to_owned(),
    );

    PostureAssessment {
        target: PostureTarget {
            path,
            pid: Some(pid),
            process_name,
        },
        captured_unix_seconds: captured_time(),
        checks,
        limitations,
    }
}

fn captured_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn base_limitations() -> Vec<String> {
    vec![
        "Observed protections reduce attack surface; they do not prove that process injection is impossible."
            .to_owned(),
        "Administrator, vulnerable-driver, and kernel-level attackers remain outside a user-mode guarantee."
            .to_owned(),
        "The file trust check validates embedded Authenticode signatures only; catalog-signature membership is not evaluated."
            .to_owned(),
    ]
}

fn check(
    kind: ProtectionKind,
    scope: AuditScope,
    verdict: PostureVerdict,
    title: impl Into<String>,
    detail: impl Into<String>,
    evidence: Option<String>,
    error: Option<String>,
) -> PostureCheck {
    PostureCheck {
        kind,
        scope,
        verdict,
        title: title.into(),
        detail: detail.into(),
        evidence,
        error,
    }
}

fn append_static_checks(checks: &mut Vec<PostureCheck>, posture: &StaticPosture) {
    let header = &posture.header;
    let aslr_pass = header.aslr_relocation_ready;
    checks.push(check(
        ProtectionKind::Aslr,
        AuditScope::Static,
        if aslr_pass {
            PostureVerdict::Pass
        } else {
            PostureVerdict::Warning
        },
        "ASLR-ready image",
        if aslr_pass {
            "The image declares DYNAMIC_BASE, does not strip relocations, and has a non-empty base-relocation directory. Runtime policy must still be queried separately."
        } else {
            "The image does not present the complete DYNAMIC_BASE plus relocation posture expected for normal ASLR. Windows policy may still alter runtime behavior."
        },
        Some(format!(
            "DYNAMIC_BASE={} | relocations_not_stripped={} | relocation_directory={} | relocation_rva={} | relocation_size={} | DllCharacteristics=0x{:04X}",
            header.dynamic_base_declared,
            header.relocations_not_stripped,
            header.base_relocation_directory_present,
            header
                .base_relocation_directory_rva
                .map(|value| format!("0x{value:08X}"))
                .unwrap_or_else(|| "unavailable".to_owned()),
            header
                .base_relocation_directory_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned()),
            header.dll_characteristics
        )),
        None,
    ));

    checks.push(check(
        ProtectionKind::HighEntropyAslr,
        AuditScope::Static,
        if !header.high_entropy_va_applicable {
            PostureVerdict::Informational
        } else if header.high_entropy_va_declared && header.aslr_relocation_ready {
            PostureVerdict::Pass
        } else {
            PostureVerdict::Warning
        },
        "High-entropy ASLR declaration",
        if !header.high_entropy_va_applicable {
            "The high-entropy VA declaration is not applicable to this non-PE32+ image."
        } else if header.high_entropy_va_declared && header.aslr_relocation_ready {
            "The PE32+ image declares HIGH_ENTROPY_VA and has the relocation prerequisites for ASLR."
        } else if header.high_entropy_va_declared {
            "The PE32+ image declares HIGH_ENTROPY_VA, but the complete relocation prerequisites for ASLR were not confirmed."
        } else {
            "The PE32+ image does not declare HIGH_ENTROPY_VA."
        },
        Some(format!(
            "PE32+={} | HIGH_ENTROPY_VA={} | ASLR_relocation_ready={}",
            posture.pe32_plus, header.high_entropy_va_declared, header.aslr_relocation_ready
        )),
        None,
    ));

    checks.push(check(
        ProtectionKind::Dep,
        AuditScope::Static,
        if header.nx_compat_declared {
            PostureVerdict::Pass
        } else {
            PostureVerdict::Warning
        },
        "DEP/NX compatibility declaration",
        if header.nx_compat_declared {
            "The image declares NX_COMPAT."
        } else {
            "NX_COMPAT is not declared in the PE header; this does not by itself prove DEP is disabled at runtime."
        },
        Some(format!("NX_COMPAT={}", header.nx_compat_declared)),
        None,
    ));

    let cfg = &posture.control_flow_guard;
    let cfg_verdict = if cfg.cfg_confirmed {
        PostureVerdict::Pass
    } else {
        PostureVerdict::Warning
    };
    checks.push(check(
        ProtectionKind::ControlFlowGuard,
        AuditScope::Static,
        cfg_verdict,
        "Control Flow Guard metadata",
        if cfg.cfg_confirmed {
            "The Guard CF header, load-config instrumentation, and any declared Guard Function Table metadata provide consistent static CFG evidence."
        } else if cfg.header_and_load_config_agree == Some(false) {
            "Guard CF metadata is inconsistent between the optional header and load configuration."
        } else if cfg.dll_characteristics_guard_cf {
            "The Guard CF header bit exists, but complete consistent instrumentation metadata was not confirmed."
        } else {
            "The image does not provide confirmed Guard CF instrumentation metadata."
        },
        Some(format!(
            "header_guard_cf={} | load_config={} | instrumented={} | header_agreement={} | guard_flags={} | table_flag={} | table_pointer={} | function_count={} | table_consistent={} | cfg_confirmed={}",
            cfg.dll_characteristics_guard_cf,
            cfg.load_config_present,
            cfg.load_config_cf_instrumented
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned()),
            cfg.header_and_load_config_agree
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned()),
            cfg.load_config_guard_flags
                .map(|value| format!("0x{value:08X}"))
                .unwrap_or_else(|| "unavailable".to_owned()),
            cfg.load_config_function_table_flag
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned()),
            cfg.guard_function_table_pointer_present
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned()),
            cfg.guard_function_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned()),
            cfg.guard_function_table_metadata_consistent
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned()),
            cfg.cfg_confirmed
        )),
        None,
    ));

    let cet = &posture.cet;
    checks.push(check(
        ProtectionKind::CetShadowStack,
        AuditScope::Static,
        match cet.cet_compat_declared {
            Some(true) => PostureVerdict::Pass,
            Some(false) => PostureVerdict::Warning,
            None => PostureVerdict::Unknown,
        },
        "CET compatibility metadata",
        match cet.cet_compat_declared {
            Some(true) => "The image declares CET compatibility metadata; live shadow-stack enforcement remains a separate check.",
            Some(false) => "Extended DLL metadata is present without CET compatibility.",
            None => "Reliable extended DLL CET metadata was not present, so static CET posture is unknown.",
        },
        cet.extended_dll_characteristics
            .map(|value| format!("DllCharacteristicsEx=0x{value:08X}")),
        None,
    ));

    let signature = &posture.authenticode;
    checks.push(check(
        ProtectionKind::AuthenticodeTrust,
        AuditScope::Static,
        match signature.status {
            AuthenticodeStatus::Valid => PostureVerdict::Pass,
            AuthenticodeStatus::NotPresent => PostureVerdict::Warning,
            AuthenticodeStatus::TrustFailure => PostureVerdict::Fail,
            AuthenticodeStatus::PresentUnverified => PostureVerdict::Unknown,
            AuthenticodeStatus::Error => PostureVerdict::Error,
        },
        "Authenticode trust",
        signature.detail.clone(),
        Some(format!(
            "certificate_table={} | parsed_certificates={} | platform_status={}",
            signature.embedded_certificate_table_present,
            signature.parsed_certificate_count,
            signature
                .platform_status_code
                .map(|value| format!("0x{:08X}", value as u32))
                .unwrap_or_else(|| "unavailable".to_owned())
        )),
        (signature.status == AuthenticodeStatus::Error).then(|| signature.detail.clone()),
    ));
}

fn append_unavailable_static_checks(checks: &mut Vec<PostureCheck>, reason: &str) {
    append_static_failure_checks(checks, PostureVerdict::Unavailable, reason);
}

fn append_static_error_checks(checks: &mut Vec<PostureCheck>, error: &StaticPostureError) {
    append_static_failure_checks(checks, PostureVerdict::Error, &error.to_string());
}

fn append_static_failure_checks(
    checks: &mut Vec<PostureCheck>,
    verdict: PostureVerdict,
    reason: &str,
) {
    for (kind, title) in [
        (ProtectionKind::Aslr, "ASLR-ready image"),
        (
            ProtectionKind::HighEntropyAslr,
            "High-entropy ASLR declaration",
        ),
        (ProtectionKind::Dep, "DEP/NX compatibility declaration"),
        (
            ProtectionKind::ControlFlowGuard,
            "Control Flow Guard metadata",
        ),
        (ProtectionKind::CetShadowStack, "CET compatibility metadata"),
        (ProtectionKind::AuthenticodeTrust, "Authenticode trust"),
    ] {
        checks.push(check(
            kind,
            AuditScope::Static,
            verdict,
            title,
            if verdict == PostureVerdict::Unavailable {
                "Static PE evidence was unavailable to this inspector."
            } else {
                "Static PE analysis failed for the selected target."
            },
            None,
            Some(reason.to_owned()),
        ));
    }
}

fn append_not_running_checks(checks: &mut Vec<PostureCheck>) {
    for (kind, title) in [
        (
            ProtectionKind::WdaRuntimeAffinity,
            "Runtime window affinity",
        ),
        (ProtectionKind::Dep, "Effective DEP policy"),
        (ProtectionKind::Aslr, "Effective ASLR policy"),
        (ProtectionKind::DynamicCodePolicy, "Dynamic-code policy"),
        (ProtectionKind::StrictHandlePolicy, "Strict-handle policy"),
        (
            ProtectionKind::ExtensionPointPolicy,
            "Extension-point policy",
        ),
        (ProtectionKind::ControlFlowGuard, "Effective CFG policy"),
        (
            ProtectionKind::BinarySignaturePolicy,
            "Binary-signature/CIG policy",
        ),
        (ProtectionKind::ImageLoadPolicy, "Image-load policy"),
        (ProtectionKind::CetShadowStack, "User shadow-stack policy"),
        (
            ProtectionKind::ProcessProtection,
            "Process protection level",
        ),
        (ProtectionKind::Debugger, "Debugger state"),
        (ProtectionKind::LoadedModules, "Loaded-module inventory"),
        (
            ProtectionKind::ExecutableMemory,
            "Executable-memory snapshot",
        ),
    ] {
        checks.push(check(
            kind,
            AuditScope::Live,
            PostureVerdict::Unknown,
            title,
            "Requires a running process; the selected file was not executed.",
            None,
            None,
        ));
    }
}

fn evidence_text(finding: &MitigationFinding) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(raw) = finding.raw_flags {
        parts.push(format!("raw=0x{raw:08X}"));
    }
    let enabled: Vec<_> = finding
        .flags
        .iter()
        .filter(|flag| flag.enabled)
        .map(|flag| flag.name.as_str())
        .collect();
    if !enabled.is_empty() {
        parts.push(format!("enabled={}", enabled.join(", ")));
    }
    (!parts.is_empty()).then(|| parts.join(" | "))
}

fn append_mitigation_check(
    checks: &mut Vec<PostureCheck>,
    kind: ProtectionKind,
    title: &str,
    finding: &MitigationFinding,
    disabled_verdict: PostureVerdict,
    enabled_detail: &str,
    disabled_detail: &str,
) {
    let (verdict, detail, error) = match finding.state {
        EvidenceState::Enabled => (PostureVerdict::Pass, enabled_detail.to_owned(), None),
        EvidenceState::Disabled => (disabled_verdict, disabled_detail.to_owned(), None),
        EvidenceState::Unavailable | EvidenceState::AccessDenied => (
            PostureVerdict::Unavailable,
            "Windows did not expose this effective policy to the current inspector.".to_owned(),
            finding.message.clone(),
        ),
        EvidenceState::Error => (
            PostureVerdict::Error,
            "The effective policy query failed.".to_owned(),
            finding.message.clone(),
        ),
        EvidenceState::Available => (
            PostureVerdict::Informational,
            "Windows returned policy metadata without a boolean enforcement classification."
                .to_owned(),
            None,
        ),
    };
    checks.push(check(
        kind,
        AuditScope::Live,
        verdict,
        title,
        detail,
        evidence_text(finding),
        error,
    ));
}

fn append_dynamic_code_check(checks: &mut Vec<PostureCheck>, finding: &MitigationFinding) {
    let (verdict, detail, error) = match finding.state {
        EvidenceState::Enabled => (
            PostureVerdict::Pass,
            "Dynamic code is prohibited without thread opt-out or remote-downgrade exceptions."
                .to_owned(),
            None,
        ),
        EvidenceState::Disabled => (
            PostureVerdict::Warning,
            "Dynamic code is allowed. This can be expected for JIT runtimes such as Electron/V8, but it leaves additional executable-memory surface."
                .to_owned(),
            None,
        ),
        EvidenceState::Available => (
            PostureVerdict::Warning,
            "Dynamic-code prohibition is present with an opt-out or remote-downgrade exception, so it is not a full process-wide block."
                .to_owned(),
            None,
        ),
        EvidenceState::Unavailable | EvidenceState::AccessDenied => (
            PostureVerdict::Unavailable,
            "Windows did not expose the effective dynamic-code policy to this inspector."
                .to_owned(),
            finding.message.clone(),
        ),
        EvidenceState::Error => (
            PostureVerdict::Error,
            "The effective dynamic-code policy query failed.".to_owned(),
            finding.message.clone(),
        ),
    };
    checks.push(check(
        ProtectionKind::DynamicCodePolicy,
        AuditScope::Live,
        verdict,
        "Dynamic-code policy",
        detail,
        evidence_text(finding),
        error,
    ));
}

fn append_live_checks(checks: &mut Vec<PostureCheck>, inspection: &ProcessInspection) {
    let mitigations = &inspection.mitigations;
    append_mitigation_check(
        checks,
        ProtectionKind::Dep,
        "Effective DEP policy",
        &mitigations.dep,
        PostureVerdict::Fail,
        "Windows reports DEP enabled for this process.",
        "Windows reports DEP disabled for this process.",
    );
    append_mitigation_check(
        checks,
        ProtectionKind::Aslr,
        "Effective ASLR policy",
        &mitigations.aslr,
        PostureVerdict::Fail,
        "At least one effective ASLR enforcement flag is enabled.",
        "No effective ASLR enforcement flag was reported.",
    );
    append_dynamic_code_check(checks, &mitigations.dynamic_code);
    append_mitigation_check(
        checks,
        ProtectionKind::StrictHandlePolicy,
        "Strict-handle policy",
        &mitigations.strict_handle_check,
        PostureVerdict::Warning,
        "Strict invalid-handle checking is enabled.",
        "Strict invalid-handle checking is not enabled.",
    );
    append_mitigation_check(
        checks,
        ProtectionKind::ExtensionPointPolicy,
        "Extension-point policy",
        &mitigations.extension_point_disable,
        PostureVerdict::Warning,
        "Legacy extension points are disabled.",
        "Legacy extension points are not disabled.",
    );
    append_mitigation_check(
        checks,
        ProtectionKind::ControlFlowGuard,
        "Effective CFG policy",
        &mitigations.control_flow_guard,
        PostureVerdict::Fail,
        "Windows reports Control Flow Guard enabled.",
        "Windows reports Control Flow Guard disabled.",
    );
    append_mitigation_check(
        checks,
        ProtectionKind::BinarySignaturePolicy,
        "Binary-signature/CIG policy",
        &mitigations.signature_policy_cig,
        PostureVerdict::Warning,
        "At least one binary-signature enforcement flag is enabled.",
        "No binary-signature enforcement flag is enabled for this process.",
    );
    append_mitigation_check(
        checks,
        ProtectionKind::ImageLoadPolicy,
        "Image-load policy",
        &mitigations.image_load,
        PostureVerdict::Warning,
        "At least one restrictive image-load policy is enabled.",
        "Remote, low-integrity, and System32-preference image-load restrictions were not reported.",
    );
    append_mitigation_check(
        checks,
        ProtectionKind::CetShadowStack,
        "User shadow-stack policy",
        &mitigations.user_shadow_stack,
        PostureVerdict::Warning,
        "Hardware-enforced user shadow stacks are enabled.",
        "Hardware-enforced user shadow stacks are not enabled for this process.",
    );

    append_protection_level(checks, inspection);
    append_debugger(checks, inspection);
    append_module_inventory(checks, inspection);
    append_memory_snapshot(checks, inspection);
    append_window_affinity(checks, inspection);
}

fn append_protection_level(checks: &mut Vec<PostureCheck>, inspection: &ProcessInspection) {
    let evidence = &inspection.protection_level;
    let (verdict, detail, proof, error) = match evidence.value.as_ref() {
        Some(level) if level.is_ppl == Some(true) => (
            PostureVerdict::Pass,
            format!("Windows reports Protected Process Light level '{}'.", level.name),
            Some(format!("level={} (0x{:08X})", level.name, level.raw_level)),
            None,
        ),
        Some(level) if level.is_protected == Some(true) => (
            PostureVerdict::Pass,
            format!("Windows reports protected-process level '{}'.", level.name),
            Some(format!("level={} (0x{:08X})", level.name, level.raw_level)),
            None,
        ),
        Some(level) if level.is_protected == Some(false) => (
            PostureVerdict::Warning,
            "The process is not protected by PPL. This is normal for ordinary desktop applications."
                .to_owned(),
            Some(format!("level={} (0x{:08X})", level.name, level.raw_level)),
            None,
        ),
        Some(level) => (
            PostureVerdict::Unknown,
            "Windows returned an unrecognized process-protection level; OroResea will not infer that it is protected or unprotected."
                .to_owned(),
            Some(format!("level={} (0x{:08X})", level.name, level.raw_level)),
            None,
        ),
        None if matches!(evidence.state, EvidenceState::Unavailable | EvidenceState::AccessDenied) => (
            PostureVerdict::Unavailable,
            "The process protection level could not be read.".to_owned(),
            None,
            evidence.message.clone(),
        ),
        None => (
            PostureVerdict::Error,
            "The process protection-level query failed.".to_owned(),
            None,
            evidence.message.clone(),
        ),
    };
    checks.push(check(
        ProtectionKind::ProcessProtection,
        AuditScope::Live,
        verdict,
        "Process protection level",
        detail,
        proof,
        error,
    ));
}

fn append_debugger(checks: &mut Vec<PostureCheck>, inspection: &ProcessInspection) {
    let evidence = &inspection.remote_debugger_present;
    let (verdict, detail, error) = match evidence.value {
        Some(true) => (
            debugger_observation_verdict(Some(true), evidence.state),
            "Windows reported a debugger attached at snapshot time. This is an observation, not proof of hostile injection; development and diagnostics tools can be legitimate.",
            None,
        ),
        Some(false) => (
            debugger_observation_verdict(Some(false), evidence.state),
            "No debugger was reported at snapshot time.",
            None,
        ),
        None if matches!(
            evidence.state,
            EvidenceState::Unavailable | EvidenceState::AccessDenied
        ) =>
        {
            (
                debugger_observation_verdict(None, evidence.state),
                "Debugger state could not be queried.",
                evidence.message.as_deref(),
            )
        }
        None => (
            debugger_observation_verdict(None, evidence.state),
            "The debugger-state query failed.",
            evidence.message.as_deref(),
        ),
    };
    checks.push(check(
        ProtectionKind::Debugger,
        AuditScope::Live,
        verdict,
        "Debugger state",
        detail,
        evidence
            .value
            .map(|value| format!("debugger_present={value}")),
        error.map(str::to_owned),
    ));
}

fn debugger_observation_verdict(value: Option<bool>, state: EvidenceState) -> PostureVerdict {
    match value {
        Some(true) => PostureVerdict::Warning,
        Some(false) => PostureVerdict::Pass,
        None if matches!(
            state,
            EvidenceState::Unavailable | EvidenceState::AccessDenied
        ) =>
        {
            PostureVerdict::Unavailable
        }
        None => PostureVerdict::Error,
    }
}

fn append_module_inventory(checks: &mut Vec<PostureCheck>, inspection: &ProcessInspection) {
    let evidence = &inspection.modules;
    let (verdict, detail, proof, error) = match evidence.value.as_ref() {
        Some(inventory) => {
            let preview = inventory
                .paths
                .iter()
                .take(12)
                .cloned()
                .collect::<Vec<_>>()
                .join(" | ");
            (
                PostureVerdict::Informational,
                format!(
                    "Inventoried {} loaded module(s). Module presence alone does not prove injection, and signer trust was not evaluated for every module.",
                    inventory.count
                ),
                Some(if preview.is_empty() {
                    format!("module_count={}", inventory.count)
                } else {
                    format!("module_count={} | first_modules={preview}", inventory.count)
                }),
                None,
            )
        }
        None if matches!(evidence.state, EvidenceState::Unavailable | EvidenceState::AccessDenied) => (
            PostureVerdict::Unavailable,
            "Loaded modules could not be enumerated, commonly because of access or cross-architecture limits."
                .to_owned(),
            None,
            evidence.message.clone(),
        ),
        None => (
            PostureVerdict::Error,
            "Loaded-module enumeration failed.".to_owned(),
            None,
            evidence.message.clone(),
        ),
    };
    checks.push(check(
        ProtectionKind::LoadedModules,
        AuditScope::Live,
        verdict,
        "Loaded-module inventory",
        detail,
        proof,
        error,
    ));
}

fn append_memory_snapshot(checks: &mut Vec<PostureCheck>, inspection: &ProcessInspection) {
    let evidence = &inspection.memory;
    let (verdict, detail, proof, error) = match evidence.value.as_ref() {
        Some(memory) if memory.rwx_region_count > 0 => (
            memory_observation_verdict(memory),
            "Writable-and-executable committed memory exists. JIT runtimes can create legitimate matches, so investigate before attributing injection."
                .to_owned(),
            Some(format!(
                "regions={} | executable_private={} ({} bytes) | rwx={} ({} bytes) | private_rwx={}",
                memory.scanned_region_count,
                memory.executable_private_region_count,
                memory.executable_private_bytes,
                memory.rwx_region_count,
                memory.rwx_bytes,
                memory.private_rwx_region_count
            )),
            None,
        ),
        Some(memory) if memory.executable_private_region_count > 0 => (
            memory_observation_verdict(memory),
            "Private executable memory exists. This is common for JIT runtimes and is not proof of injection."
                .to_owned(),
            Some(format!(
                "regions={} | executable_private={} ({} bytes) | rwx=0",
                memory.scanned_region_count,
                memory.executable_private_region_count,
                memory.executable_private_bytes
            )),
            None,
        ),
        Some(memory) => (
            memory_observation_verdict(memory),
            "No committed private executable or RWX memory region was observed at snapshot time."
                .to_owned(),
            Some(format!("regions={}", memory.scanned_region_count)),
            None,
        ),
        None if matches!(evidence.state, EvidenceState::Unavailable | EvidenceState::AccessDenied) => (
            PostureVerdict::Unavailable,
            "Executable-memory metadata could not be queried.".to_owned(),
            None,
            evidence.message.clone(),
        ),
        None => (
            PostureVerdict::Error,
            "Executable-memory metadata query failed.".to_owned(),
            None,
            evidence.message.clone(),
        ),
    };
    checks.push(check(
        ProtectionKind::ExecutableMemory,
        AuditScope::Live,
        verdict,
        "Executable-memory snapshot",
        detail,
        proof,
        error,
    ));
}

fn memory_observation_verdict(memory: &MemoryRegionSummary) -> PostureVerdict {
    if memory.rwx_region_count > 0 || memory.executable_private_region_count > 0 {
        PostureVerdict::Warning
    } else {
        PostureVerdict::Pass
    }
}

fn append_window_affinity(checks: &mut Vec<PostureCheck>, inspection: &ProcessInspection) {
    let evidence = &inspection.windows;
    let Some(windows) = evidence.value.as_ref() else {
        checks.push(check(
            ProtectionKind::WdaRuntimeAffinity,
            AuditScope::Live,
            if matches!(
                evidence.state,
                EvidenceState::Unavailable | EvidenceState::AccessDenied
            ) {
                PostureVerdict::Unavailable
            } else {
                PostureVerdict::Error
            },
            "Runtime window affinity",
            "Top-level windows or their display affinity could not be inspected.",
            None,
            evidence.message.clone(),
        ));
        return;
    };

    if windows.is_empty() {
        checks.push(check(
            ProtectionKind::WdaRuntimeAffinity,
            AuditScope::Live,
            PostureVerdict::Unavailable,
            "Runtime window affinity",
            "No top-level window belonging to this PID was present on the current desktop.",
            Some("top_level_windows=0".to_owned()),
            None,
        ));
        return;
    }

    let mut visible_protected = 0usize;
    let mut visible_unprotected = 0usize;
    let mut visible_unavailable = 0usize;
    let mut hidden = 0usize;
    let mut descriptions = Vec::new();
    for window in windows {
        if !window.visible {
            hidden += 1;
        }
        match window.display_affinity.value.as_ref() {
            Some(affinity) => {
                let mode = match affinity.kind {
                    DisplayAffinityKind::None => {
                        if window.visible {
                            visible_unprotected += 1;
                        }
                        "WDA_NONE"
                    }
                    DisplayAffinityKind::Monitor => {
                        if window.visible {
                            visible_protected += 1;
                        }
                        "WDA_MONITOR"
                    }
                    DisplayAffinityKind::ExcludeFromCapture => {
                        if window.visible {
                            visible_protected += 1;
                        }
                        "WDA_EXCLUDEFROMCAPTURE"
                    }
                    DisplayAffinityKind::Unknown => {
                        if window.visible {
                            visible_unavailable += 1;
                        }
                        "UNKNOWN"
                    }
                };
                descriptions.push(format!(
                    "HWND 0x{:X} {} {} (0x{:X})",
                    window.hwnd,
                    if window.visible { "visible" } else { "hidden" },
                    mode,
                    affinity.raw_value
                ));
            }
            None => {
                if window.visible {
                    visible_unavailable += 1;
                }
                descriptions.push(format!(
                    "HWND 0x{:X} {} query unavailable{}",
                    window.hwnd,
                    if window.visible { "visible" } else { "hidden" },
                    window
                        .display_affinity
                        .message
                        .as_deref()
                        .map(|message| format!(": {message}"))
                        .unwrap_or_default()
                ));
            }
        }
    }

    let verdict = visible_window_affinity_verdict(
        visible_protected,
        visible_unprotected,
        visible_unavailable,
    );
    checks.push(check(
        ProtectionKind::WdaRuntimeAffinity,
        AuditScope::Live,
        verdict,
        "Runtime window affinity",
        format!(
            "Visible windows: {} protected, {} WDA_NONE, {} unavailable. Hidden top-level windows: {}. WDA is a capture hint for compatible DWM capture paths, not DRM or an anti-injection boundary.",
            visible_protected, visible_unprotected, visible_unavailable, hidden
        ),
        Some(descriptions.join(" | ")),
        None,
    ));
}

fn visible_window_affinity_verdict(
    protected: usize,
    unprotected: usize,
    unavailable: usize,
) -> PostureVerdict {
    let visible_total = protected + unprotected + unavailable;
    if visible_total == 0 {
        PostureVerdict::Informational
    } else if protected > 0 && unprotected == 0 && unavailable == 0 {
        PostureVerdict::Pass
    } else if protected > 0 {
        PostureVerdict::Warning
    } else if unprotected > 0 {
        // No policy baseline was selected, so WDA_NONE is an observation rather
        // than a compliance failure.
        PostureVerdict::Informational
    } else {
        PostureVerdict::Unavailable
    }
}

fn append_system_gaps(checks: &mut Vec<PostureCheck>) {
    checks.push(check(
        ProtectionKind::Wdac,
        AuditScope::System,
        PostureVerdict::Unavailable,
        "WDAC enforcement",
        "A process snapshot cannot prove which Windows Defender Application Control policy decisions governed every image. System policy and Code Integrity event telemetry are required.",
        None,
        None,
    ));
    checks.push(check(
        ProtectionKind::HandleAccessMonitoring,
        AuditScope::System,
        PostureVerdict::Unavailable,
        "Process-handle access history",
        "Historical OpenProcess/handle access requires continuous ETW, auditing, EDR, or driver-backed telemetry and is not inferred from a point-in-time snapshot.",
        None,
        None,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_inventory_is_sorted_when_available() {
        if !live_posture::is_supported() {
            return;
        }
        let processes = enumerate_processes(false).expect("Windows process inventory should work");
        assert!(!processes.is_empty());
        assert!(processes.windows(2).all(|pair| {
            (pair[0].executable_name.to_ascii_lowercase(), pair[0].pid)
                <= (pair[1].executable_name.to_ascii_lowercase(), pair[1].pid)
        }));
    }

    #[test]
    fn self_assessment_keeps_system_gaps_unavailable() {
        if !live_posture::is_supported() {
            return;
        }
        let assessment = assess_process(std::process::id());
        assert!(assessment.target.pid.is_some());
        assert!(assessment.checks.iter().any(|item| {
            item.kind == ProtectionKind::Wdac && item.verdict == PostureVerdict::Unavailable
        }));
        assert!(assessment.checks.iter().any(|item| {
            item.kind == ProtectionKind::HandleAccessMonitoring
                && item.verdict == PostureVerdict::Unavailable
        }));
    }

    #[test]
    fn debugger_is_an_observation_not_a_hard_failure() {
        assert_eq!(
            debugger_observation_verdict(Some(true), EvidenceState::Enabled),
            PostureVerdict::Warning
        );
        assert_eq!(
            debugger_observation_verdict(Some(false), EvidenceState::Disabled),
            PostureVerdict::Pass
        );
        assert_eq!(
            debugger_observation_verdict(None, EvidenceState::AccessDenied),
            PostureVerdict::Unavailable
        );
    }

    #[test]
    fn executable_memory_is_contextual_not_a_hard_failure() {
        let mut memory = MemoryRegionSummary {
            scanned_region_count: 10,
            executable_private_region_count: 0,
            executable_private_bytes: 0,
            rwx_region_count: 0,
            rwx_bytes: 0,
            private_rwx_region_count: 0,
        };
        assert_eq!(memory_observation_verdict(&memory), PostureVerdict::Pass);
        memory.rwx_region_count = 1;
        memory.rwx_bytes = 4096;
        assert_eq!(memory_observation_verdict(&memory), PostureVerdict::Warning);
    }

    #[test]
    fn wda_none_is_not_a_failure_without_a_policy_baseline() {
        assert_eq!(
            visible_window_affinity_verdict(0, 1, 0),
            PostureVerdict::Informational
        );
        assert_eq!(
            visible_window_affinity_verdict(1, 0, 0),
            PostureVerdict::Pass
        );
        assert_eq!(
            visible_window_affinity_verdict(1, 1, 0),
            PostureVerdict::Warning
        );
        assert_eq!(
            visible_window_affinity_verdict(0, 0, 1),
            PostureVerdict::Unavailable
        );
    }
}
