use crate::model::{ReportSummary, ScanResult};
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
:root{color-scheme:dark;font-family:Inter,Segoe UI,sans-serif;background:#0b0f14;color:#e7edf5}*{box-sizing:border-box}body{margin:0}header{display:flex;gap:16px;align-items:center;padding:28px 6vw;border-bottom:1px solid #25303b;background:#10161e}.brand{display:grid;place-items:center;width:52px;height:52px;border-radius:15px;background:linear-gradient(145deg,#e6ba57,#8e641c);color:#111;font-weight:900}h1{margin:0;font-size:24px}header p{margin:5px 0 0;color:#91a0af}main{width:min(1200px,92vw);margin:26px auto}.source{display:grid;gap:8px}.source code,article code{color:#a7b6c6;word-break:break-all}.summary{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:22px 0}.summary div{display:grid;gap:4px;padding:16px;border:1px solid #25303b;border-radius:12px;background:#111821}.summary b{font-size:24px}.summary span{color:#91a0af}.high b{color:#ff6f78}.medium b{color:#ffb55c}.low b{color:#e4cf67}.clean b{color:#68d6a4}article{padding:20px;margin:14px 0;border:1px solid #25303b;border-radius:14px;background:#111821}.row{display:flex;gap:14px;align-items:flex-start}.row h2{margin:0 0 4px;font-size:18px}.badge{min-width:76px;padding:6px 9px;border-radius:8px;text-align:center;font-size:12px;font-weight:800;background:#283341}.badge.high{background:#59232a;color:#ff9aa1}.badge.medium{background:#583b1b;color:#ffc578}.badge.low{background:#4b451b;color:#f0dc79}.badge.clean{background:#173f33;color:#7be1b3}.badge.info{background:#183e51;color:#79d4f0}.badge.error{background:#45252c;color:#ff9da5}dl{display:grid;grid-template-columns:150px 1fr;gap:7px 14px;margin:18px 0}dt{color:#91a0af}.hash{font-family:ui-monospace,monospace;word-break:break-all}.finding{margin-top:10px;padding:12px;border-left:3px solid #c89a3c;background:#0d131a}.finding p{margin:5px 0 0;color:#bec8d3;line-height:1.45}footer{padding:24px 0;color:#91a0af}@media(max-width:700px){.summary{grid-template-columns:repeat(2,1fr)}dl{grid-template-columns:1fr}.row{display:grid}}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RiskLevel;
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

    fn generated_nonce() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
}
