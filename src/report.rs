use crate::model::{AuditScope, PostureAssessment, PostureSummary, ReportSummary, ScanResult};
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Serialize)]
struct Report<'a> {
    application: &'static str,
    version: &'static str,
    generated_unix_seconds: u64,
    source: &'a str,
    summary: ReportSummary,
    results: &'a [ScanResult],
}

fn report<'a>(source: &'a str, results: &'a [ScanResult]) -> Report<'a> {
    Report {
        application: "OroResea",
        version: env!("CARGO_PKG_VERSION"),
        generated_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        source,
        summary: ReportSummary::from_results(results),
        results,
    }
}

pub fn write_json(path: &Path, source: &str, results: &[ScanResult]) -> Result<(), String> {
    let file = File::create(path).map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(file, &report(source, results)).map_err(|error| error.to_string())
}

pub fn write_csv(path: &Path, results: &[ScanResult]) -> Result<(), String> {
    let mut writer = csv::Writer::from_path(path).map_err(|error| error.to_string())?;
    writer
        .write_record([
            "level",
            "confidence",
            "file",
            "path",
            "kind",
            "architecture",
            "size_bytes",
            "sha256",
            "embedded_signature",
            "evidence",
            "error",
        ])
        .map_err(|error| error.to_string())?;

    for result in results {
        let confidence = result
            .findings
            .first()
            .map(|finding| finding.confidence.to_string())
            .unwrap_or_default();
        let evidence = result
            .findings
            .iter()
            .map(|finding| format!("{}: {}", finding.title, finding.detail))
            .collect::<Vec<_>>()
            .join(" | ");
        writer
            .write_record([
                result.highest_level.label().to_owned(),
                confidence,
                result.file_name.clone(),
                result.path.to_string_lossy().into_owned(),
                result.file_kind.clone(),
                result.architecture.clone(),
                result.size_bytes.to_string(),
                result.sha256.clone(),
                result.embedded_signature.to_string(),
                evidence,
                result.error.clone().unwrap_or_default(),
            ])
            .map_err(|error| error.to_string())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

pub fn write_html(path: &Path, source: &str, results: &[ScanResult]) -> Result<(), String> {
    let summary = ReportSummary::from_results(results);
    let mut file = File::create(path).map_err(|error| error.to_string())?;
    write!(
        file,
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>OroResea report</title><style>{}</style></head><body>",
        CSS
    )
    .map_err(io_error)?;
    write!(
        file,
        "<header><div class=\"brand\">OR</div><div><h1>OroResea analysis report</h1><p>Read-only static WDA evidence scan</p></div></header><main><section class=\"source\"><b>Source</b><code>{}</code></section>",
        escape_html(source)
    )
    .map_err(io_error)?;
    write!(
        file,
        "<section class=\"summary\"><div><b>{}</b><span>Files</span></div><div class=\"high\"><b>{}</b><span>High</span></div><div class=\"medium\"><b>{}</b><span>Medium</span></div><div class=\"low\"><b>{}</b><span>Low</span></div><div class=\"clean\"><b>{}</b><span>Clean</span></div></section>",
        summary.files_scanned, summary.high, summary.medium, summary.low, summary.clean
    )
    .map_err(io_error)?;
    file.write_all(b"<section class=\"results\">")
        .map_err(io_error)?;

    for result in results {
        let level = result.highest_level.label().to_ascii_lowercase();
        write!(
            file,
            "<article><div class=\"row\"><span class=\"badge {}\">{}</span><div><h2>{}</h2><code>{}</code></div></div><dl><dt>Type</dt><dd>{}</dd><dt>Architecture</dt><dd>{}</dd><dt>SHA-256</dt><dd class=\"hash\">{}</dd><dt>Signature blob</dt><dd>{}</dd></dl>",
            level,
            escape_html(result.highest_level.label()),
            escape_html(&result.file_name),
            escape_html(&result.path.to_string_lossy()),
            escape_html(&result.file_kind),
            escape_html(&result.architecture),
            escape_html(&result.sha256),
            if result.embedded_signature { "Present (not trust-validated)" } else { "Not found" },
        )
        .map_err(io_error)?;
        for finding in &result.findings {
            write!(
                file,
                "<div class=\"finding\"><b>{} ({}%)</b><p>{}</p></div>",
                escape_html(&finding.title),
                finding.confidence,
                escape_html(&finding.detail)
            )
            .map_err(io_error)?;
        }
        if let Some(error) = &result.error {
            write!(
                file,
                "<div class=\"finding error\">{}</div>",
                escape_html(error)
            )
            .map_err(io_error)?;
        }
        file.write_all(b"</article>").map_err(io_error)?;
    }

    file.write_all(b"</section><footer>OroResea reports static evidence, not proof of runtime behavior. No inspected binary was executed.</footer></main></body></html>")
        .map_err(io_error)
}

#[derive(Serialize)]
struct PostureReport<'a> {
    application: &'static str,
    version: &'static str,
    schema_version: u32,
    generated_unix_seconds: u64,
    summary: PostureSummary,
    assessment: &'a PostureAssessment,
}

fn posture_report(assessment: &PostureAssessment) -> PostureReport<'_> {
    PostureReport {
        application: "OroResea",
        version: env!("CARGO_PKG_VERSION"),
        schema_version: 1,
        generated_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        summary: assessment.summary(),
        assessment,
    }
}

pub fn write_posture_json(path: &Path, assessment: &PostureAssessment) -> Result<(), String> {
    let file = File::create(path).map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(file, &posture_report(assessment))
        .map_err(|error| error.to_string())
}

pub fn write_posture_csv(path: &Path, assessment: &PostureAssessment) -> Result<(), String> {
    let mut writer = csv::Writer::from_path(path).map_err(|error| error.to_string())?;
    writer
        .write_record([
            "captured_unix_seconds",
            "pid",
            "process_name",
            "path",
            "scope",
            "protection",
            "verdict",
            "title",
            "detail",
            "evidence",
            "error",
        ])
        .map_err(|error| error.to_string())?;

    for check in &assessment.checks {
        writer
            .write_record([
                assessment.captured_unix_seconds.to_string(),
                assessment
                    .target
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_default(),
                assessment.target.process_name.clone().unwrap_or_default(),
                assessment
                    .target
                    .path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                check.scope.label().to_owned(),
                check.kind.label().to_owned(),
                check.verdict.label().to_owned(),
                check.title.clone(),
                check.detail.clone(),
                check.evidence.clone().unwrap_or_default(),
                check.error.clone().unwrap_or_default(),
            ])
            .map_err(|error| error.to_string())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

pub fn write_posture_html(path: &Path, assessment: &PostureAssessment) -> Result<(), String> {
    let summary = assessment.summary();
    let mut file = File::create(path).map_err(|error| error.to_string())?;
    let target = assessment
        .target
        .process_name
        .as_deref()
        .or_else(|| {
            assessment
                .target
                .path
                .as_ref()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
        })
        .unwrap_or("Unknown target");
    let path_text = assessment
        .target
        .path
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Unavailable".to_owned());

    write!(
        file,
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>OroResea protection posture</title><style>{}</style></head><body>",
        CSS
    )
    .map_err(io_error)?;
    write!(
        file,
        "<header><div class=\"brand\">OR</div><div><h1>Protection posture report</h1><p>Read-only static and live Windows observations</p></div></header><main><section class=\"source\"><b>{}</b><code>{}</code><span>PID: {} &middot; captured: {}</span></section>",
        escape_html(target),
        escape_html(&path_text),
        assessment
            .target
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "not running".to_owned()),
        assessment.captured_unix_seconds,
    )
    .map_err(io_error)?;
    write!(
        file,
        "<section class=\"summary posture-summary\"><div class=\"pass\"><b>{}</b><span>Pass</span></div><div class=\"fail\"><b>{}</b><span>Fail</span></div><div class=\"warning\"><b>{}</b><span>Warning</span></div><div class=\"info\"><b>{}</b><span>Informational</span></div><div class=\"unknown\"><b>{}</b><span>Unknown</span></div><div class=\"unavailable\"><b>{}</b><span>Unavailable</span></div><div class=\"error\"><b>{}</b><span>Error</span></div></section>",
        summary.pass,
        summary.fail,
        summary.warning,
        summary.informational,
        summary.unknown,
        summary.unavailable,
        summary.errors
    )
    .map_err(io_error)?;

    for scope in [AuditScope::Static, AuditScope::Live, AuditScope::System] {
        write!(
            file,
            "<section class=\"results\"><h2>{} CHECKS</h2>",
            scope.label()
        )
        .map_err(io_error)?;
        for check in assessment
            .checks
            .iter()
            .filter(|check| check.scope == scope)
        {
            let class = check.verdict.label().to_ascii_lowercase();
            write!(
                file,
                "<article><div class=\"row\"><span class=\"badge {}\">{}</span><div><h2>{}</h2><code>{}</code></div></div><div class=\"finding\"><p>{}</p>",
                escape_html(&class),
                escape_html(check.verdict.label()),
                escape_html(&check.title),
                escape_html(check.kind.label()),
                escape_html(&check.detail),
            )
            .map_err(io_error)?;
            if let Some(evidence) = &check.evidence {
                write!(file, "<p><b>Evidence:</b> {}</p>", escape_html(evidence))
                    .map_err(io_error)?;
            }
            if let Some(error) = &check.error {
                write!(file, "<p><b>Error:</b> {}</p>", escape_html(error)).map_err(io_error)?;
            }
            file.write_all(b"</div></article>").map_err(io_error)?;
        }
        file.write_all(b"</section>").map_err(io_error)?;
    }

    file.write_all(b"<section class=\"results\"><h2>LIMITATIONS</h2><article><ul>")
        .map_err(io_error)?;
    for limitation in &assessment.limitations {
        write!(file, "<li>{}</li>", escape_html(limitation)).map_err(io_error)?;
    }
    file.write_all(b"</ul></article></section><footer>OroResea reports time-stamped observable posture, not proof that injection is impossible.</footer></main></body></html>")
        .map_err(io_error)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn io_error(error: io::Error) -> String {
    error.to_string()
}

const CSS: &str = r#"
:root{color-scheme:dark;font-family:Inter,Segoe UI,sans-serif;background:#0b0f14;color:#e7edf5}*{box-sizing:border-box}body{margin:0}header{display:flex;gap:16px;align-items:center;padding:28px 6vw;border-bottom:1px solid #25303b;background:#10161e}.brand{display:grid;place-items:center;width:52px;height:52px;border-radius:15px;background:linear-gradient(145deg,#e6ba57,#8e641c);color:#111;font-weight:900}h1{margin:0;font-size:24px}header p{margin:5px 0 0;color:#91a0af}main{width:min(1200px,92vw);margin:26px auto}.source{display:grid;gap:8px}.source code,article code{color:#a7b6c6;word-break:break-all}.summary{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:22px 0}.posture-summary{grid-template-columns:repeat(auto-fit,minmax(120px,1fr))}.summary div{display:grid;gap:4px;padding:16px;border:1px solid #25303b;border-radius:12px;background:#111821}.summary b{font-size:24px}.summary span{color:#91a0af}.high b,.fail b,.error b{color:#ff6f78}.medium b,.warning b{color:#ffb55c}.low b{color:#e4cf67}.clean b,.pass b{color:#68d6a4}.info b{color:#79d4f0}.unknown b{color:#aeb9c5}.unavailable b{color:#9b8fb7}article{padding:20px;margin:14px 0;border:1px solid #25303b;border-radius:14px;background:#111821}.row{display:flex;gap:14px;align-items:flex-start}.row h2{margin:0 0 4px;font-size:18px}.badge{min-width:76px;padding:6px 9px;border-radius:8px;text-align:center;font-size:12px;font-weight:800;background:#283341}.badge.high,.badge.fail{background:#59232a;color:#ff9aa1}.badge.medium,.badge.warning{background:#583b1b;color:#ffc578}.badge.low{background:#4b451b;color:#f0dc79}.badge.clean,.badge.pass{background:#173f33;color:#7be1b3}.badge.info{background:#183e51;color:#79d4f0}.badge.unknown{background:#2a3440;color:#c5d0dc}.badge.unavailable{background:#352d48;color:#c3b6e4}.badge.error{background:#45252c;color:#ff9da5}dl{display:grid;grid-template-columns:150px 1fr;gap:7px 14px;margin:18px 0}dt{color:#91a0af}.hash{font-family:ui-monospace,monospace;word-break:break-all}.finding{margin-top:10px;padding:12px;border-left:3px solid #c89a3c;background:#0d131a}.finding p{margin:5px 0 0;color:#bec8d3;line-height:1.45}footer{padding:24px 0;color:#91a0af}@media(max-width:700px){.summary{grid-template-columns:repeat(2,1fr)}dl{grid-template-columns:1fr}.row{display:grid}}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PostureCheck, PostureTarget, PostureVerdict, ProtectionKind, RiskLevel};
    use std::{fs, path::PathBuf};

    fn sample_result() -> ScanResult {
        ScanResult {
            path: PathBuf::from(r"C:\sample\clean.exe"),
            file_name: "clean.exe".to_owned(),
            file_kind: "Windows PE / executable".to_owned(),
            architecture: "x64".to_owned(),
            size_bytes: 42,
            sha256: "abcd".to_owned(),
            embedded_signature: false,
            highest_level: RiskLevel::Clean,
            findings: Vec::new(),
            relevant_imports: Vec::new(),
            error: None,
        }
    }

    fn sample_posture() -> PostureAssessment {
        PostureAssessment {
            target: PostureTarget {
                path: Some(PathBuf::from(r"C:\sample\probe&tool.exe")),
                pid: Some(4242),
                process_name: Some("probe<tool>".to_owned()),
            },
            captured_unix_seconds: 1_725_000_000,
            checks: vec![
                PostureCheck {
                    kind: ProtectionKind::ControlFlowGuard,
                    scope: AuditScope::Static,
                    verdict: PostureVerdict::Pass,
                    title: "CFG <declared>".to_owned(),
                    detail: "Header & load configuration agree.".to_owned(),
                    evidence: Some("GuardFlags=0x100, table=present".to_owned()),
                    error: None,
                },
                PostureCheck {
                    kind: ProtectionKind::DynamicCodePolicy,
                    scope: AuditScope::Live,
                    verdict: PostureVerdict::Warning,
                    title: "Dynamic code policy".to_owned(),
                    detail: "Dynamic code is permitted for this process.".to_owned(),
                    evidence: Some("ProhibitDynamicCode=false".to_owned()),
                    error: None,
                },
                PostureCheck {
                    kind: ProtectionKind::Wdac,
                    scope: AuditScope::System,
                    verdict: PostureVerdict::Unavailable,
                    title: "WDAC system policy".to_owned(),
                    detail: "Requires system policy telemetry.".to_owned(),
                    evidence: None,
                    error: Some("policy source unavailable".to_owned()),
                },
            ],
            limitations: vec!["A snapshot cannot prove <injection> is impossible.".to_owned()],
        }
    }

    #[test]
    fn exports_all_report_formats() {
        let nonce = format!("{}-{}", std::process::id(), generated_nonce());
        let base = std::env::temp_dir().join(format!("ororesea-report-{nonce}"));
        let json_path = base.with_extension("json");
        let csv_path = base.with_extension("csv");
        let html_path = base.with_extension("html");
        let results = vec![sample_result()];

        write_json(&json_path, r"C:\sample", &results).expect("JSON export should succeed");
        write_csv(&csv_path, &results).expect("CSV export should succeed");
        write_html(&html_path, r"C:\sample", &results).expect("HTML export should succeed");

        let json: serde_json::Value = serde_json::from_reader(
            File::open(&json_path).expect("JSON report should be readable"),
        )
        .expect("JSON report should parse");
        assert_eq!(json["summary"]["files_scanned"], 1);
        assert!(fs::read_to_string(&csv_path).unwrap().contains("clean.exe"));
        assert!(
            fs::read_to_string(&html_path)
                .unwrap()
                .contains("OroResea analysis report")
        );

        let _ = fs::remove_file(json_path);
        let _ = fs::remove_file(csv_path);
        let _ = fs::remove_file(html_path);
    }

    #[test]
    fn posture_json_has_versioned_schema_and_complete_summary() {
        let path = unique_report_path("posture-schema", "json");
        write_posture_json(&path, &sample_posture()).expect("posture JSON should export");

        let json: serde_json::Value = serde_json::from_reader(
            File::open(&path).expect("posture JSON report should be readable"),
        )
        .expect("posture JSON report should parse");
        assert_eq!(json["application"], "OroResea");
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["summary"]["pass"], 1);
        assert_eq!(json["summary"]["warning"], 1);
        assert_eq!(json["summary"]["unavailable"], 1);
        assert_eq!(json["summary"]["fail"], 0);
        assert_eq!(json["assessment"]["target"]["pid"], 4242);
        assert_eq!(
            json["assessment"]["checks"][1]["kind"],
            "dynamic_code_policy"
        );
        assert_eq!(json["assessment"]["checks"][1]["scope"], "live");
        assert_eq!(json["assessment"]["checks"][1]["verdict"], "warning");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn posture_csv_writes_exactly_one_record_per_check() {
        let path = unique_report_path("posture-rows", "csv");
        let assessment = sample_posture();
        write_posture_csv(&path, &assessment).expect("posture CSV should export");

        let mut reader = csv::Reader::from_path(&path).expect("posture CSV should be readable");
        let headers = reader.headers().expect("CSV should have headers").clone();
        let records = reader
            .records()
            .collect::<Result<Vec<_>, _>>()
            .expect("all CSV records should parse");
        assert_eq!(records.len(), assessment.checks.len());
        assert_eq!(headers.iter().filter(|name| *name == "verdict").count(), 1);
        assert_eq!(records[0].get(1), Some("4242"));
        assert_eq!(records[0].get(4), Some("STATIC"));
        assert_eq!(records[0].get(6), Some("PASS"));
        assert_eq!(records[0].get(9), Some("GuardFlags=0x100, table=present"));
        assert_eq!(records[2].get(10), Some("policy source unavailable"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn posture_html_escapes_content_and_groups_every_scope() {
        let path = unique_report_path("posture-html", "html");
        write_posture_html(&path, &sample_posture()).expect("posture HTML should export");

        let html = fs::read_to_string(&path).expect("posture HTML should be readable");
        assert!(html.contains("probe&lt;tool&gt;"));
        assert!(html.contains(r"C:\sample\probe&amp;tool.exe"));
        assert!(html.contains("CFG &lt;declared&gt;"));
        assert!(html.contains("Header &amp; load configuration agree."));
        assert!(html.contains("A snapshot cannot prove &lt;injection&gt; is impossible."));
        assert!(!html.contains("probe<tool>"));

        let static_at = html
            .find("STATIC CHECKS")
            .expect("static group should exist");
        let live_at = html.find("LIVE CHECKS").expect("live group should exist");
        let system_at = html
            .find("SYSTEM CHECKS")
            .expect("system group should exist");
        assert!(static_at < live_at && live_at < system_at);
        for class in [
            "badge.pass",
            "badge.fail",
            "badge.warning",
            "badge.info",
            "badge.unknown",
            "badge.unavailable",
            "badge.error",
        ] {
            assert!(html.contains(class), "missing CSS for {class}");
        }

        let _ = fs::remove_file(path);
    }

    fn unique_report_path(name: &str, extension: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "ororesea-{name}-{}-{}",
                std::process::id(),
                generated_nonce()
            ))
            .with_extension(extension)
    }

    fn generated_nonce() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
}
