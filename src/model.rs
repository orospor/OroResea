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
