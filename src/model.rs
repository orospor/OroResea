use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    High,
    Medium,
    Low,
    Informational,
    Clean,
    Error,
}

impl RiskLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Informational => "INFO",
            Self::Clean => "CLEAN",
            Self::Error => "ERROR",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::High => 5,
            Self::Medium => 4,
            Self::Low => 3,
            Self::Informational => 2,
            Self::Clean => 1,
            Self::Error => 0,
        }
    }

    pub fn is_flagged(self) -> bool {
        matches!(self, Self::High | Self::Medium | Self::Low)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    DirectImport,
    DynamicResolution,
    ApiString,
    WdaMarker,
    InspectionApi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub level: RiskLevel,
    pub confidence: u8,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditScope {
    Static,
    Live,
    System,
}

impl AuditScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Static => "STATIC",
            Self::Live => "LIVE",
            Self::System => "SYSTEM",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureVerdict {
    Pass,
    Fail,
    Warning,
    Informational,
    Unknown,
    Unavailable,
    Error,
}

impl PostureVerdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Warning => "WARNING",
            Self::Informational => "INFO",
            Self::Unknown => "UNKNOWN",
            Self::Unavailable => "UNAVAILABLE",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionKind {
    WdaRuntimeAffinity,
    Dep,
    Aslr,
    HighEntropyAslr,
    ControlFlowGuard,
    CetShadowStack,
    AuthenticodeTrust,
    DynamicCodePolicy,
    StrictHandlePolicy,
    BinarySignaturePolicy,
    ExtensionPointPolicy,
    ImageLoadPolicy,
    ProcessProtection,
    Debugger,
    LoadedModules,
    ExecutableMemory,
    Wdac,
    HandleAccessMonitoring,
}

impl ProtectionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::WdaRuntimeAffinity => "Runtime WDA",
            Self::Dep => "DEP",
            Self::Aslr => "ASLR",
            Self::HighEntropyAslr => "High-entropy ASLR",
            Self::ControlFlowGuard => "Control Flow Guard",
            Self::CetShadowStack => "CET / shadow stack",
            Self::AuthenticodeTrust => "Authenticode",
            Self::DynamicCodePolicy => "Dynamic code",
            Self::StrictHandlePolicy => "Strict handles",
            Self::BinarySignaturePolicy => "Binary signature / CIG",
            Self::ExtensionPointPolicy => "Extension points",
            Self::ImageLoadPolicy => "Image loading",
            Self::ProcessProtection => "Process protection",
            Self::Debugger => "Debugger",
            Self::LoadedModules => "Loaded modules",
            Self::ExecutableMemory => "Executable memory",
            Self::Wdac => "WDAC",
            Self::HandleAccessMonitoring => "Handle-access telemetry",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureCheck {
    pub kind: ProtectionKind,
    pub scope: AuditScope,
    pub verdict: PostureVerdict,
    pub title: String,
    pub detail: String,
    pub evidence: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureTarget {
    pub path: Option<PathBuf>,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureAssessment {
    pub target: PostureTarget,
    pub captured_unix_seconds: u64,
    pub checks: Vec<PostureCheck>,
    pub limitations: Vec<String>,
}

impl PostureAssessment {
    pub fn summary(&self) -> PostureSummary {
        PostureSummary::from_checks(&self.checks)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostureSummary {
    pub pass: usize,
    pub fail: usize,
    pub warning: usize,
    pub informational: usize,
    pub unknown: usize,
    pub unavailable: usize,
    pub errors: usize,
}

impl PostureSummary {
    pub fn from_checks(checks: &[PostureCheck]) -> Self {
        let mut summary = Self::default();
        for check in checks {
            match check.verdict {
                PostureVerdict::Pass => summary.pass += 1,
                PostureVerdict::Fail => summary.fail += 1,
                PostureVerdict::Warning => summary.warning += 1,
                PostureVerdict::Informational => summary.informational += 1,
                PostureVerdict::Unknown => summary.unknown += 1,
                PostureVerdict::Unavailable => summary.unavailable += 1,
                PostureVerdict::Error => summary.errors += 1,
            }
        }
        summary
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: PathBuf,
    pub file_name: String,
    pub file_kind: String,
    pub architecture: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub embedded_signature: bool,
    pub highest_level: RiskLevel,
    pub findings: Vec<Evidence>,
    pub relevant_imports: Vec<String>,
    pub error: Option<String>,
}

impl ScanResult {
    pub fn failed(path: PathBuf, message: impl Into<String>) -> Self {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Unknown file")
            .to_owned();

        Self {
            path,
            file_name,
            file_kind: "Unreadable".to_owned(),
            architecture: "Unknown".to_owned(),
            size_bytes: 0,
            sha256: String::new(),
            embedded_signature: false,
            highest_level: RiskLevel::Error,
            findings: Vec::new(),
            relevant_imports: Vec::new(),
            error: Some(message.into()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ReportSummary {
    pub files_scanned: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
    pub clean: usize,
    pub errors: usize,
}

impl ReportSummary {
    pub fn from_results(results: &[ScanResult]) -> Self {
        let mut summary = Self {
            files_scanned: results.len(),
            ..Self::default()
        };

        for result in results {
            match result.highest_level {
                RiskLevel::High => summary.high += 1,
                RiskLevel::Medium => summary.medium += 1,
                RiskLevel::Low => summary.low += 1,
                RiskLevel::Informational => summary.informational += 1,
                RiskLevel::Clean => summary.clean += 1,
                RiskLevel::Error => summary.errors += 1,
            }
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(verdict: PostureVerdict) -> PostureCheck {
        PostureCheck {
            kind: ProtectionKind::Dep,
            scope: AuditScope::Live,
            verdict,
            title: "test".to_owned(),
            detail: "test".to_owned(),
            evidence: None,
            error: None,
        }
    }

    #[test]
    fn posture_summary_keeps_unavailable_distinct_from_failure() {
        let summary = PostureSummary::from_checks(&[
            check(PostureVerdict::Pass),
            check(PostureVerdict::Fail),
            check(PostureVerdict::Unavailable),
            check(PostureVerdict::Unknown),
        ]);
        assert_eq!(summary.pass, 1);
        assert_eq!(summary.fail, 1);
        assert_eq!(summary.unavailable, 1);
        assert_eq!(summary.unknown, 1);
    }
}
