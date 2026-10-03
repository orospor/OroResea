use crate::model::{Evidence, EvidenceKind, RiskLevel, ScanResult};
use goblin::Object;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};
use walkdir::WalkDir;
use zip::ZipArchive;

const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
const PE_EXTENSIONS: &[&str] = &["exe", "dll", "node", "ocx", "cpl", "scr", "sys"];
const JAVA_EXTENSIONS: &[&str] = &["jar", "war", "ear", "jmod", "class"];
const MAX_ARCHIVE_ENTRIES: usize = 20_000;
const MAX_ARCHIVE_DEPTH: usize = 2;
const MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DETAILED_FINDINGS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    pub wda: bool,
    pub process_mitigations: bool,
    pub dll_loading: bool,
    pub java: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            wda: true,
            process_mitigations: true,
            dll_loading: true,
            java: true,
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedImport {
    dll: String,
    name: String,
    delayed: bool,
}

#[derive(Debug)]
pub enum ScanMessage {
    Started {
        total: usize,
    },
    Progress {
        current: usize,
        total: usize,
        path: PathBuf,
    },
    Result(ScanResult),
    Finished {
        cancelled: bool,
        elapsed: Duration,
    },
}

pub fn spawn_scan_with_options(
    root: PathBuf,
    options: ScanOptions,
) -> (Receiver<ScanMessage>, Arc<AtomicBool>) {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);

    thread::spawn(move || run_scan(root, tx, worker_cancel, options));
    (rx, cancel)
}

fn run_scan(root: PathBuf, tx: Sender<ScanMessage>, cancel: Arc<AtomicBool>, options: ScanOptions) {
    let started = Instant::now();
    let candidates = collect_candidates(&root, options);
    let total = candidates.len();
    if tx.send(ScanMessage::Started { total }).is_err() {
        return;
    }

    for (index, path) in candidates.into_iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            let _ = tx.send(ScanMessage::Finished {
                cancelled: true,
                elapsed: started.elapsed(),
            });
            return;
        }

        let current = index + 1;
        if tx
            .send(ScanMessage::Progress {
                current,
                total,
                path: path.clone(),
            })
            .is_err()
        {
            return;
        }

        let result = analyze_file_with_options(&path, options);
        if tx.send(ScanMessage::Result(result)).is_err() {
            return;
        }
    }

    let _ = tx.send(ScanMessage::Finished {
        cancelled: false,
        elapsed: started.elapsed(),
    });
}

fn collect_candidates(root: &Path, options: ScanOptions) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_owned()];
    }

    let mut paths: Vec<PathBuf> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| is_candidate(path, options))
        .collect();

    paths.sort_by_cached_key(|path| path.to_string_lossy().to_ascii_lowercase());
    paths
}

fn is_candidate(path: &Path, options: ScanOptions) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            let ext = ext.to_ascii_lowercase();
            PE_EXTENSIONS.contains(&ext.as_str())
                || (options.java && JAVA_EXTENSIONS.contains(&ext.as_str()))
        })
        .unwrap_or(false)
}

#[cfg(test)]
pub fn analyze_file(path: &Path) -> ScanResult {
    analyze_file_with_options(path, ScanOptions::default())
}

pub fn analyze_file_with_options(path: &Path, options: ScanOptions) -> ScanResult {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return ScanResult::failed(path.to_owned(), error.to_string()),
    };

    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if options.java && extension == "class" && metadata.len() > MAX_ENTRY_BYTES {
        return ScanResult::failed(
            path.to_owned(),
            format!(
                "Java class is larger than the {} MiB inspection limit",
                MAX_ENTRY_BYTES / 1024 / 1024
            ),
        );
    }

    if metadata.len() > MAX_FILE_SIZE {
        return ScanResult::failed(
            path.to_owned(),
            format!(
                "File is larger than the {} MiB safety limit",
                MAX_FILE_SIZE / 1024 / 1024
            ),
        );
    }

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => return ScanResult::failed(path.to_owned(), error.to_string()),
    };

    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Unknown file")
        .to_owned();

    if JAVA_EXTENSIONS.contains(&extension.as_str()) && !options.java {
        return ScanResult {
            path: path.to_owned(),
            file_name,
            file_kind: "Java file (scan disabled)".to_owned(),
            architecture: "Unknown".to_owned(),
            size_bytes: metadata.len(),
            sha256,
            embedded_signature: false,
            highest_level: RiskLevel::Error,
            findings: Vec::new(),
            relevant_imports: Vec::new(),
            error: Some("Java analysis is disabled by the current scan option".to_owned()),
        };
    }
    if extension == "class" {
        return analyze_java_class(path, &file_name, metadata.len(), sha256, &bytes, options);
    }
    if matches!(extension.as_str(), "jar" | "war" | "ear" | "jmod") {
        return analyze_java_archive(path, &file_name, metadata.len(), sha256, &bytes, options);
    }

    let pe = match Object::parse(&bytes) {
        Ok(Object::PE(pe)) => pe,
        Ok(_) => {
            return ScanResult {
                path: path.to_owned(),
                file_name,
                file_kind: "Not a Windows PE".to_owned(),
                architecture: "Unknown".to_owned(),
                size_bytes: metadata.len(),
                sha256,
                embedded_signature: false,
                highest_level: RiskLevel::Clean,
                findings: Vec::new(),
                relevant_imports: Vec::new(),
                error: None,
            };
        }
        Err(error) => {
            return ScanResult::failed(path.to_owned(), format!("PE parsing failed: {error}"));
        }
    };

    let mut imports: Vec<ParsedImport> = pe
        .imports
        .iter()
        .map(|import| ParsedImport {
            dll: import.dll.to_owned(),
            name: import.name.to_string(),
            delayed: false,
        })
        .collect();
    imports.extend(parse_delay_imports(&bytes, &pe));
    let is_managed = contains_ascii_ci(&bytes, b"mscoree.dll")
        || contains_ascii_ci(&bytes, b"System.Runtime.InteropServices");
    let findings = classify_evidence_with_options(&imports, &bytes, is_managed, options);
    let highest_level = findings
        .iter()
        .map(|finding| finding.level)
        .max_by_key(|level| level.rank())
        .unwrap_or(RiskLevel::Clean);

    let relevant_imports = imports
        .iter()
        .filter(|import| is_relevant_import(&import.name, options))
        .map(|import| {
            format!(
                "{}!{}{}",
                import.dll,
                import.name,
                if import.delayed { " [delay]" } else { "" }
            )
        })
        .collect();

    ScanResult {
        path: path.to_owned(),
        file_name,
        file_kind: if is_managed {
            "Windows PE / managed".to_owned()
        } else if pe.is_lib {
            "Windows PE / DLL".to_owned()
        } else {
            "Windows PE / executable".to_owned()
        },
        architecture: architecture_name(pe.header.coff_header.machine).to_owned(),
        size_bytes: metadata.len(),
        sha256,
        embedded_signature: has_embedded_signature(&bytes),
        highest_level,
        findings,
        relevant_imports,
        error: None,
    }
}

#[derive(Default)]
struct JavaScan {
    classes: usize,
    bridge_classes: usize,
    native_images: usize,
    architectures: BTreeSet<String>,
    findings: Vec<Evidence>,
    relevant_imports: Vec<String>,
    expanded_bytes: u64,
    entries_seen: usize,
    skipped_large: usize,
    skipped_depth: usize,
    skipped_invalid: usize,
    skipped_unsupported: usize,
    skipped_budget: usize,
    dropped_findings: usize,
}

impl JavaScan {
    fn push(&mut self, finding: Evidence) {
        if self.findings.len() < MAX_DETAILED_FINDINGS {
            self.findings.push(finding);
        } else {
            self.dropped_findings += 1;
        }
    }

    fn finish(
        mut self,
        path: &Path,
        file_name: &str,
        file_kind: String,
        size_bytes: u64,
        sha256: String,
    ) -> ScanResult {
        self.findings.push(Evidence {
            kind: EvidenceKind::JavaBytecode,
            level: RiskLevel::Informational,
            confidence: 95,
            title: "Java bytecode inventory".to_owned(),
            detail: format!(
                "Inspected {} class file(s), {} class(es) with a native bridge marker, and {} embedded Windows PE image(s). This inventory does not prove that any method executed.",
                self.classes, self.bridge_classes, self.native_images
            ),
        });
        let skipped = self.skipped_large
            + self.skipped_depth
            + self.skipped_invalid
            + self.skipped_unsupported
            + self.skipped_budget;
        if skipped > 0 || self.dropped_findings > 0 {
            self.findings.push(Evidence {
                kind: EvidenceKind::JavaBytecode,
                level: RiskLevel::Informational,
                confidence: 95,
                title: "Java archive inspection incomplete".to_owned(),
                detail: format!(
                    "Skipped entries: oversized {}, nesting limit {}, malformed {}, unsupported ZIP compression/read {}, scan budget {}; omitted {} detailed finding(s). Limits: {} entries, {} MiB per entry, {} MiB expanded total, nested depth {}.",
                    self.skipped_large,
                    self.skipped_depth,
                    self.skipped_invalid,
                    self.skipped_unsupported,
                    self.skipped_budget,
                    self.dropped_findings,
                    MAX_ARCHIVE_ENTRIES,
                    MAX_ENTRY_BYTES / 1024 / 1024,
                    MAX_EXPANDED_BYTES / 1024 / 1024,
                    MAX_ARCHIVE_DEPTH,
                ),
            });
        }
        self.findings
            .sort_by_key(|finding| std::cmp::Reverse(finding.level.rank()));
        let highest_level = self
            .findings
            .iter()
            .map(|finding| finding.level)
            .max_by_key(|level| level.rank())
            .unwrap_or(RiskLevel::Clean);
        let architecture = if self.architectures.is_empty() && self.classes > 0 {
            "JVM bytecode".to_owned()
        } else if self.architectures.is_empty() {
            "Unknown".to_owned()
        } else if self.classes == 0 {
            self.architectures
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            format!(
                "JVM bytecode + {}",
                self.architectures
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        ScanResult {
            path: path.to_owned(),
            file_name: file_name.to_owned(),
            file_kind,
            architecture,
            size_bytes,
            sha256,
            embedded_signature: false,
            highest_level,
            findings: self.findings,
            relevant_imports: self.relevant_imports,
            error: None,
        }
    }
}

fn analyze_java_class(
    path: &Path,
    file_name: &str,
    size_bytes: u64,
    sha256: String,
    bytes: &[u8],
    options: ScanOptions,
) -> ScanResult {
    let mut scan = JavaScan::default();
    if !inspect_class(bytes, file_name, options, &mut scan) {
        return ScanResult::failed(path.to_owned(), "Invalid Java class file");
    }
    scan.finish(path, file_name, "Java class".to_owned(), size_bytes, sha256)
}

fn analyze_java_archive(
    path: &Path,
    file_name: &str,
    size_bytes: u64,
    sha256: String,
    bytes: &[u8],
    options: ScanOptions,
) -> ScanResult {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("jar")
        .to_ascii_lowercase();
    let mut scan = JavaScan::default();
    if let Err(error) = inspect_archive(bytes, &extension, 0, "", options, &mut scan) {
        return ScanResult::failed(
            path.to_owned(),
            format!("Java archive parsing failed: {error}"),
        );
    }
    scan.finish(
        path,
        file_name,
        format!("Java archive ({})", extension.to_ascii_uppercase()),
        size_bytes,
        sha256,
    )
}

fn inspect_archive(
    bytes: &[u8],
    extension: &str,
    depth: usize,
    prefix: &str,
    options: ScanOptions,
    scan: &mut JavaScan,
) -> Result<(), String> {
    // A JMOD has a four-byte header before the ZIP payload.
    let zip_bytes = if extension == "jmod" && bytes.starts_with(b"JM\x01\x00") {
        &bytes[4..]
    } else {
        bytes
    };
    let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).map_err(|error| error.to_string())?;
    let entry_count = archive.len();
    for index in 0..entry_count {
        if scan.entries_seen >= MAX_ARCHIVE_ENTRIES {
            scan.skipped_budget += entry_count - index;
            break;
        }
        scan.entries_seen += 1;
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(_) => {
                scan.skipped_unsupported += 1;
                continue;
            }
        };
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_owned();
        let member_extension = Path::new(&name)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_class = member_extension == "class";
        let is_native = PE_EXTENSIONS.contains(&member_extension.as_str());
        let is_nested = matches!(member_extension.as_str(), "jar" | "war" | "ear" | "jmod");
        if !(is_class || is_native || is_nested) {
            continue;
        }
        if is_nested && depth >= MAX_ARCHIVE_DEPTH {
            scan.skipped_depth += 1;
            continue;
        }
        if entry.size() > MAX_ENTRY_BYTES {
            scan.skipped_large += 1;
            continue;
        }
        let remaining = MAX_EXPANDED_BYTES.saturating_sub(scan.expanded_bytes);
        if remaining == 0 || entry.size() > remaining {
            scan.skipped_budget += 1;
            continue;
        }
        let allowed = MAX_ENTRY_BYTES.min(remaining);
        let mut contents = Vec::with_capacity(entry.size().min(allowed) as usize);
        match (&mut entry).take(allowed + 1).read_to_end(&mut contents) {
            Ok(_) if contents.len() as u64 <= allowed => {}
            Ok(_) => {
                scan.skipped_large += 1;
                continue;
            }
            Err(_) => {
                scan.skipped_unsupported += 1;
                continue;
            }
        }
        scan.expanded_bytes += contents.len() as u64;
        let display_name = safe_member_name(&format!("{prefix}{name}"));
        if is_class {
            if !inspect_class(&contents, &display_name, options, scan) {
                scan.skipped_invalid += 1;
            }
        } else if is_native {
            inspect_native_member(&contents, &display_name, options, scan);
        } else if inspect_archive(
            &contents,
            &member_extension,
            depth + 1,
            &format!("{display_name}!/"),
            options,
            scan,
        )
        .is_err()
        {
            scan.skipped_invalid += 1;
        }
    }
    Ok(())
}

fn safe_member_name(name: &str) -> String {
    name.chars()
        .take(240)
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

fn inspect_native_member(bytes: &[u8], member: &str, options: ScanOptions, scan: &mut JavaScan) {
    let Ok(Object::PE(pe)) = Object::parse(bytes) else {
        return;
    };
    scan.native_images += 1;
    scan.architectures
        .insert(architecture_name(pe.header.coff_header.machine).to_owned());
    let mut imports: Vec<ParsedImport> = pe
        .imports
        .iter()
        .map(|import| ParsedImport {
            dll: import.dll.to_owned(),
            name: import.name.to_string(),
            delayed: false,
        })
        .collect();
    imports.extend(parse_delay_imports(bytes, &pe));
    let is_managed = contains_ascii_ci(bytes, b"mscoree.dll");
    for mut finding in classify_evidence_with_options(&imports, bytes, is_managed, options) {
        finding.detail = format!("Embedded PE {member}: {}", finding.detail);
        scan.push(finding);
    }
    for import in imports
        .iter()
        .filter(|import| is_relevant_import(&import.name, options))
    {
        if scan.relevant_imports.len() >= 128 {
            break;
        }
        scan.relevant_imports.push(format!(
            "{member}: {}!{}{}",
            import.dll,
            import.name,
            if import.delayed { " [delay]" } else { "" }
        ));
    }
}

#[derive(Default)]
struct ClassSignals {
    wda_api: bool,
    wda_value: bool,
    mitigation_api: bool,
    signature_policy: bool,
    native_bridge: bool,
}

fn inspect_class(bytes: &[u8], member: &str, options: ScanOptions, scan: &mut JavaScan) -> bool {
    let Some(signals) = class_signals(bytes) else {
        return false;
    };
    scan.classes += 1;
    if signals.native_bridge {
        scan.bridge_classes += 1;
    }
    if options.wda && signals.wda_api {
        scan.push(Evidence {
            kind: if signals.native_bridge {
                EvidenceKind::JavaNativeBridge
            } else {
                EvidenceKind::JavaBytecode
            },
            level: if signals.native_bridge {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            },
            confidence: if signals.native_bridge { 70 } else { 45 },
            title: if signals.native_bridge {
                "Java/native WDA binding reference".to_owned()
            } else {
                "WDA API name in Java bytecode".to_owned()
            },
            detail: format!(
                "Class {member} references SetWindowDisplayAffinity{}{}. Static bytecode cannot prove the call executes, which affinity value is used, or whether Windows accepted it.",
                if signals.native_bridge {
                    " and a JNA/JNI/foreign-function bridge marker"
                } else {
                    ""
                },
                if signals.wda_value {
                    " plus a named WDA value"
                } else {
                    ""
                }
            ),
        });
    } else if options.wda && signals.wda_value {
        scan.push(Evidence {
            kind: EvidenceKind::JavaBytecode,
            level: RiskLevel::Informational,
            confidence: 40,
            title: "WDA value name in Java bytecode".to_owned(),
            detail: format!(
                "Class {member} contains a WDA_EXCLUDEFROMCAPTURE or WDA_MONITOR name. A value name alone does not show a Windows API call."
            ),
        });
    }
    if options.process_mitigations && signals.mitigation_api && signals.signature_policy {
        scan.push(Evidence {
            kind: if signals.native_bridge {
                EvidenceKind::JavaNativeBridge
            } else {
                EvidenceKind::JavaBytecode
            },
            level: RiskLevel::Informational,
            confidence: if signals.native_bridge { 55 } else { 40 },
            title: "Java process-signature policy reference".to_owned(),
            detail: format!(
                "Class {member} contains SetProcessMitigationPolicy and a signature-policy name. This is a static capability hint, not evidence that CIG is active in a JVM process."
            ),
        });
    }
    true
}

fn class_signals(bytes: &[u8]) -> Option<ClassSignals> {
    if bytes.get(..4)? != b"\xca\xfe\xba\xbe" {
        return None;
    }
    let mut offset = 8; // magic and major/minor version
    let constant_count = next_u16_be(bytes, &mut offset)? as usize;
    if constant_count == 0 {
        return None;
    }
    let mut constants = Vec::new();
    let mut index = 1;
    while index < constant_count {
        let tag = *take_bytes(bytes, &mut offset, 1)?.first()?;
        match tag {
            1 => {
                let length = next_u16_be(bytes, &mut offset)? as usize;
                constants.push(take_bytes(bytes, &mut offset, length)?);
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => {
                take_bytes(bytes, &mut offset, 4)?;
            }
            5 | 6 => {
                take_bytes(bytes, &mut offset, 8)?;
                index += 1;
            }
            7 | 8 | 16 | 19 | 20 => {
                take_bytes(bytes, &mut offset, 2)?;
            }
            15 => {
                take_bytes(bytes, &mut offset, 3)?;
            }
            _ => return None,
        }
        index += 1;
    }
    take_bytes(bytes, &mut offset, 6)?; // class access, this, super
    let interfaces = next_u16_be(bytes, &mut offset)? as usize;
    take_bytes(bytes, &mut offset, interfaces.checked_mul(2)?)?;
    let fields = next_u16_be(bytes, &mut offset)?;
    for _ in 0..fields {
        take_bytes(bytes, &mut offset, 6)?;
        let attributes = next_u16_be(bytes, &mut offset)?;
        skip_attributes(bytes, &mut offset, attributes)?;
    }
    let methods = next_u16_be(bytes, &mut offset)?;
    let mut native_methods = 0;
    for _ in 0..methods {
        let flags = next_u16_be(bytes, &mut offset)?;
        if flags & 0x0100 != 0 {
            native_methods += 1;
        }
        take_bytes(bytes, &mut offset, 4)?; // name and descriptor indices
        let attributes = next_u16_be(bytes, &mut offset)?;
        skip_attributes(bytes, &mut offset, attributes)?;
    }
    let attributes = next_u16_be(bytes, &mut offset)?;
    skip_attributes(bytes, &mut offset, attributes)?;
    if offset != bytes.len() {
        return None;
    }
    let contains = |needle: &[u8]| {
        constants
            .iter()
            .any(|constant| contains_ascii_ci(constant, needle))
    };
    let native_bridge = native_methods > 0
        || (contains(b"java/lang/System") && (contains(b"loadLibrary") || contains(b"load")))
        || contains(b"com/sun/jna/")
        || contains(b"jnr/ffi/")
        || contains(b"java/lang/foreign/")
        || contains(b"jdk/incubator/foreign/")
        || contains(b"org/bytedeco/javacpp/");
    Some(ClassSignals {
        wda_api: contains(b"SetWindowDisplayAffinity"),
        wda_value: contains(b"WDA_EXCLUDEFROMCAPTURE") || contains(b"WDA_MONITOR"),
        mitigation_api: contains(b"SetProcessMitigationPolicy"),
        signature_policy: contains(b"ProcessSignaturePolicy") || contains(b"MicrosoftSignedOnly"),
        native_bridge,
    })
}

fn skip_attributes(bytes: &[u8], offset: &mut usize, count: u16) -> Option<()> {
    for _ in 0..count {
        take_bytes(bytes, offset, 2)?; // attribute name index
        let length = next_u32_be(bytes, offset)? as usize;
        take_bytes(bytes, offset, length)?;
    }
    Some(())
}

fn take_bytes<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(length)?;
    let slice = bytes.get(*offset..end)?;
    *offset = end;
    Some(slice)
}

fn next_u16_be(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        take_bytes(bytes, offset, 2)?.try_into().ok()?,
    ))
}

fn next_u32_be(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        take_bytes(bytes, offset, 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
fn classify_evidence(imports: &[ParsedImport], bytes: &[u8], is_managed: bool) -> Vec<Evidence> {
    classify_evidence_with_options(imports, bytes, is_managed, ScanOptions::default())
}

fn classify_evidence_with_options(
    imports: &[ParsedImport],
    bytes: &[u8],
    is_managed: bool,
    options: ScanOptions,
) -> Vec<Evidence> {
    let mut findings = Vec::new();

    if options.wda {
        classify_wda_evidence(imports, bytes, is_managed, &mut findings);
    }
    if options.process_mitigations {
        classify_mitigation_capabilities(imports, bytes, &mut findings);
    }
    if options.dll_loading {
        classify_dll_capabilities(imports, bytes, &mut findings);
    }

    findings.sort_by_key(|finding| std::cmp::Reverse(finding.level.rank()));
    findings
}

fn classify_wda_evidence(
    imports: &[ParsedImport],
    bytes: &[u8],
    is_managed: bool,
    findings: &mut Vec<Evidence>,
) {
    let set_import = imports
        .iter()
        .find(|import| import.name.eq_ignore_ascii_case("SetWindowDisplayAffinity"));
    let get_import = imports
        .iter()
        .find(|import| import.name.eq_ignore_ascii_case("GetWindowDisplayAffinity"));
    let resolver_import = imports.iter().any(|import| {
        import.name.eq_ignore_ascii_case("GetProcAddress")
            || import.name.eq_ignore_ascii_case("LdrGetProcedureAddress")
    });
    let set_string = contains_text_ci(bytes, "SetWindowDisplayAffinity");
    let get_string = contains_text_ci(bytes, "GetWindowDisplayAffinity");
    let resolver_string = contains_text_ci(bytes, "GetProcAddress")
        || contains_text_ci(bytes, "LdrGetProcedureAddress");
    let exclusion_marker = contains_text_ci(bytes, "WDA_EXCLUDEFROMCAPTURE");
    let monitor_marker = contains_text_ci(bytes, "WDA_MONITOR");

    if let Some(import) = set_import {
        findings.push(Evidence {
            kind: EvidenceKind::DirectImport,
            level: RiskLevel::High,
            confidence: if import.delayed { 92 } else { 95 },
            title: if import.delayed {
                "Delay-loaded SetWindowDisplayAffinity import".to_owned()
            } else {
                "Direct SetWindowDisplayAffinity import".to_owned()
            },
            detail: "A PE import table references the API that can apply or clear window capture restrictions. Static analysis cannot determine which affinity value is used on every code path.".to_owned(),
        });
    } else if set_string && (resolver_import || resolver_string || is_managed) {
        findings.push(Evidence {
            kind: EvidenceKind::DynamicResolution,
            level: RiskLevel::Medium,
            confidence: if is_managed { 80 } else { 75 },
            title: if is_managed {
                "Probable managed/native WDA binding".to_owned()
            } else {
                "Probable dynamically resolved WDA call".to_owned()
            },
            detail: "The API name is embedded in the file and a runtime symbol-resolution mechanism is present. This pattern can avoid a normal PE import entry.".to_owned(),
        });
    } else if set_string {
        findings.push(Evidence {
            kind: EvidenceKind::ApiString,
            level: RiskLevel::Low,
            confidence: 45,
            title: "SetWindowDisplayAffinity string found".to_owned(),
            detail: "The API name exists as ASCII or UTF-16 text, but no direct import or resolver combination was confirmed.".to_owned(),
        });
    }

    if exclusion_marker || monitor_marker {
        let markers = match (exclusion_marker, monitor_marker) {
            (true, true) => "WDA_EXCLUDEFROMCAPTURE and WDA_MONITOR",
            (true, false) => "WDA_EXCLUDEFROMCAPTURE",
            (false, true) => "WDA_MONITOR",
            (false, false) => unreachable!(),
        };
        findings.push(Evidence {
            kind: EvidenceKind::WdaMarker,
            level: RiskLevel::Low,
            confidence: 40,
            title: "Named WDA protection marker found".to_owned(),
            detail: format!("Embedded text references {markers}. This is supporting evidence only; names may occur in documentation or diagnostic UI."),
        });
    }

    if get_import.is_some() || (get_string && set_import.is_none() && !set_string) {
        findings.push(Evidence {
            kind: EvidenceKind::InspectionApi,
            level: RiskLevel::Informational,
            confidence: if get_import.is_some() { 95 } else { 50 },
            title: "Display-affinity inspection capability".to_owned(),
            detail: "GetWindowDisplayAffinity reads protection state; by itself it does not apply capture blocking.".to_owned(),
        });
    }
}

fn classify_mitigation_capabilities(
    imports: &[ParsedImport],
    bytes: &[u8],
    findings: &mut Vec<Evidence>,
) {
    push_api_capability(
        findings,
        imports,
        bytes,
        "SetProcessMitigationPolicy",
        EvidenceKind::MitigationApi,
        "Process-mitigation setter capability",
        "The image can request a process mitigation such as a binary-signature/CIG or dynamic-code policy. The import does not identify the selected policy, flags, timing, or whether Windows accepted it.",
    );
    push_api_capability(
        findings,
        imports,
        bytes,
        "GetProcessMitigationPolicy",
        EvidenceKind::MitigationApi,
        "Process-mitigation inspection capability",
        "The image can read an effective process-mitigation policy. Inspection capability alone does not enable CIG or another mitigation.",
    );

    let setter_present = imports.iter().any(|import| {
        import
            .name
            .eq_ignore_ascii_case("SetProcessMitigationPolicy")
    }) || contains_text_ci(bytes, "SetProcessMitigationPolicy");
    let signature_marker = contains_text_ci(bytes, "ProcessSignaturePolicy")
        || contains_text_ci(bytes, "MicrosoftSignedOnly")
        || contains_text_ci(bytes, "microsoft_signed_only");
    if setter_present && signature_marker {
        findings.push(Evidence {
            kind: EvidenceKind::MitigationApi,
            level: RiskLevel::Informational,
            confidence: 70,
            title: "Probable binary-signature/CIG policy capability".to_owned(),
            detail: "A process-mitigation setter and a signature-policy marker occur in the same image. This supports CIG capability only; active enforcement requires GetProcessMitigationPolicy readback from a running process.".to_owned(),
        });
    }
}

fn classify_dll_capabilities(imports: &[ParsedImport], bytes: &[u8], findings: &mut Vec<Evidence>) {
    for (api, title, detail) in [
        (
            "SetDefaultDllDirectories",
            "Default DLL-directory hardening capability",
            "The image can restrict default DLL search locations. Static presence does not prove the function ran successfully or reveal the requested flags.",
        ),
        (
            "SetDllDirectoryW",
            "DLL search-directory control capability",
            "The image can change process-local DLL search behavior. Static presence does not reveal the supplied directory or effective runtime state.",
        ),
        (
            "AddDllDirectory",
            "Explicit DLL-directory capability",
            "The image can add a process DLL search directory. This may support controlled loading or broaden search depending on the runtime path and flags.",
        ),
    ] {
        push_api_capability(
            findings,
            imports,
            bytes,
            api,
            EvidenceKind::DllSearchHardening,
            title,
            detail,
        );
    }

    for api in ["LoadLibraryExW", "LoadLibraryW", "LoadLibraryA"] {
        push_api_capability(
            findings,
            imports,
            bytes,
            api,
            EvidenceKind::LoaderCapability,
            "Explicit Windows image-loader capability",
            "The image can request a DLL load. This is common Windows functionality and does not by itself indicate injection, malicious behavior, or a successful load.",
        );
    }
}

fn push_api_capability(
    findings: &mut Vec<Evidence>,
    imports: &[ParsedImport],
    bytes: &[u8],
    api: &str,
    kind: EvidenceKind,
    title: &str,
    detail: &str,
) {
    if let Some(import) = imports
        .iter()
        .find(|import| import.name.eq_ignore_ascii_case(api))
    {
        findings.push(Evidence {
            kind,
            level: RiskLevel::Informational,
            confidence: if import.delayed { 92 } else { 95 },
            title: if import.delayed {
                format!("Delay-loaded {title}")
            } else {
                title.to_owned()
            },
            detail: format!("{detail} Imported API: {api}."),
        });
    } else if contains_text_ci(bytes, api) {
        findings.push(Evidence {
            kind,
            level: RiskLevel::Informational,
            confidence: 45,
            title: format!("{title} string found"),
            detail: format!("The API name {api} occurs as ASCII or UTF-16 text, but a matching PE import was not confirmed. {detail}"),
        });
    }
}

fn is_relevant_import(name: &str, options: ScanOptions) -> bool {
    (options.wda
        && (name.eq_ignore_ascii_case("SetWindowDisplayAffinity")
            || name.eq_ignore_ascii_case("GetWindowDisplayAffinity")
            || name.eq_ignore_ascii_case("GetProcAddress")))
        || (options.process_mitigations
            && (name.eq_ignore_ascii_case("SetProcessMitigationPolicy")
                || name.eq_ignore_ascii_case("GetProcessMitigationPolicy")))
        || (options.dll_loading
            && (name.eq_ignore_ascii_case("SetDefaultDllDirectories")
                || name.eq_ignore_ascii_case("SetDllDirectoryW")
                || name.eq_ignore_ascii_case("AddDllDirectory")
                || name.to_ascii_lowercase().starts_with("loadlibrary")))
}

fn parse_delay_imports(bytes: &[u8], pe: &goblin::pe::PE<'_>) -> Vec<ParsedImport> {
    let Some(layout) = pe_layout(bytes) else {
        return Vec::new();
    };
    let directory_entry = layout.data_directory_offset + (13 * 8);
    let descriptor_rva = read_u32(bytes, directory_entry).unwrap_or(0);
    let descriptor_size = read_u32(bytes, directory_entry + 4).unwrap_or(0) as usize;
    if descriptor_rva == 0 || descriptor_size < 32 {
        return Vec::new();
    }

    let Some(mut descriptor_offset) = rva_to_offset(descriptor_rva, pe, bytes.len()) else {
        return Vec::new();
    };
    let descriptor_end = descriptor_offset
        .saturating_add(descriptor_size)
        .min(bytes.len());
    let mut imports = Vec::new();

    while descriptor_offset.saturating_add(32) <= descriptor_end {
        let attributes = read_u32(bytes, descriptor_offset).unwrap_or(0);
        let dll_address = read_u32(bytes, descriptor_offset + 4).unwrap_or(0) as u64;
        let int_address = read_u32(bytes, descriptor_offset + 16).unwrap_or(0) as u64;
        if attributes == 0 && dll_address == 0 && int_address == 0 {
            break;
        }

        let uses_rvas = attributes & 1 != 0;
        let Some(dll_rva) = address_to_rva(dll_address, layout.image_base, uses_rvas) else {
            descriptor_offset += 32;
            continue;
        };
        let Some(dll_offset) = rva_to_offset(dll_rva, pe, bytes.len()) else {
            descriptor_offset += 32;
            continue;
        };
        let dll = read_c_string(bytes, dll_offset).unwrap_or_else(|| "Unknown DLL".to_owned());

        let Some(int_rva) = address_to_rva(int_address, layout.image_base, uses_rvas) else {
            descriptor_offset += 32;
            continue;
        };
        let Some(mut thunk_offset) = rva_to_offset(int_rva, pe, bytes.len()) else {
            descriptor_offset += 32;
            continue;
        };
        let pointer_size = if layout.is_64 { 8 } else { 4 };
        for _ in 0..65_536 {
            let Some(thunk) = read_pointer(bytes, thunk_offset, layout.is_64) else {
                break;
            };
            if thunk == 0 {
                break;
            }
            let ordinal_mask = if layout.is_64 { 1u64 << 63 } else { 1u64 << 31 };
            if thunk & ordinal_mask == 0
                && let Some(name_rva) = address_to_rva(thunk, layout.image_base, uses_rvas)
                && let Some(name_offset) = rva_to_offset(name_rva, pe, bytes.len())
                && let Some(name) = read_c_string(bytes, name_offset.saturating_add(2))
            {
                imports.push(ParsedImport {
                    dll: dll.clone(),
                    name,
                    delayed: true,
                });
            }
            thunk_offset = match thunk_offset.checked_add(pointer_size) {
                Some(offset) => offset,
                None => break,
            };
        }

        descriptor_offset += 32;
    }

    imports
}

#[derive(Clone, Copy)]
struct PeLayout {
    data_directory_offset: usize,
    image_base: u64,
    is_64: bool,
}

fn pe_layout(bytes: &[u8]) -> Option<PeLayout> {
    let pe_offset = read_u32(bytes, 0x3c)? as usize;
    if bytes.get(pe_offset..pe_offset.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let optional_offset = pe_offset.checked_add(24)?;
    match read_u16(bytes, optional_offset)? {
        0x10b => Some(PeLayout {
            data_directory_offset: optional_offset.checked_add(96)?,
            image_base: read_u32(bytes, optional_offset.checked_add(28)?)? as u64,
            is_64: false,
        }),
        0x20b => Some(PeLayout {
            data_directory_offset: optional_offset.checked_add(112)?,
            image_base: read_u64(bytes, optional_offset.checked_add(24)?)?,
            is_64: true,
        }),
        _ => None,
    }
}

fn address_to_rva(address: u64, image_base: u64, uses_rvas: bool) -> Option<u32> {
    let rva = if uses_rvas {
        address
    } else {
        address.checked_sub(image_base)?
    };
    u32::try_from(rva).ok()
}

fn rva_to_offset(rva: u32, pe: &goblin::pe::PE<'_>, file_len: usize) -> Option<usize> {
    for section in &pe.sections {
        let start = section.virtual_address;
        let span = section.virtual_size.max(section.size_of_raw_data);
        let end = start.checked_add(span)?;
        if (start..end).contains(&rva) {
            let delta = rva.checked_sub(start)?;
            if delta >= section.size_of_raw_data {
                return None;
            }
            let offset = section.pointer_to_raw_data.checked_add(delta)? as usize;
            return (offset < file_len).then_some(offset);
        }
    }

    // RVAs in the PE headers map directly to file offsets.
    let offset = rva as usize;
    (offset < file_len).then_some(offset)
}

fn read_c_string(bytes: &[u8], offset: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let length = tail.iter().position(|byte| *byte == 0)?.min(4096);
    let raw = tail.get(..length)?;
    (!raw.is_empty()).then(|| String::from_utf8_lossy(raw).into_owned())
}

fn read_pointer(bytes: &[u8], offset: usize, is_64: bool) -> Option<u64> {
    if is_64 {
        read_u64(bytes, offset)
    } else {
        read_u32(bytes, offset).map(u64::from)
    }
}

fn contains_text_ci(bytes: &[u8], needle: &str) -> bool {
    contains_ascii_ci(bytes, needle.as_bytes()) || contains_utf16le_ci(bytes, needle)
}

fn contains_ascii_ci(bytes: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || bytes.len() < needle.len() {
        return false;
    }

    bytes
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn contains_utf16le_ci(bytes: &[u8], needle: &str) -> bool {
    let wide: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    contains_ascii_ci(bytes, &wide)
}

fn architecture_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x8664 => "x64",
        0xaa64 => "ARM64",
        0x01c0 | 0x01c2 | 0x01c4 => "ARM",
        0x0200 => "Itanium",
        _ => "Unknown",
    }
}

fn has_embedded_signature(bytes: &[u8]) -> bool {
    let pe_offset = read_u32(bytes, 0x3c).map(|value| value as usize);
    let Some(pe_offset) = pe_offset else {
        return false;
    };
    if bytes.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        return false;
    }

    let optional_offset = pe_offset + 24;
    let Some(magic) = read_u16(bytes, optional_offset) else {
        return false;
    };
    let data_directory_offset = match magic {
        0x10b => optional_offset + 96,
        0x20b => optional_offset + 112,
        _ => return false,
    };

    // IMAGE_DIRECTORY_ENTRY_SECURITY is data-directory slot 4. Its first
    // field is a file offset rather than an RVA.
    let entry = data_directory_offset + (4 * 8);
    let certificate_offset = read_u32(bytes, entry).unwrap_or(0) as usize;
    let certificate_size = read_u32(bytes, entry + 4).unwrap_or(0) as usize;
    certificate_offset > 0
        && certificate_size >= 8
        && certificate_offset
            .checked_add(certificate_size)
            .is_some_and(|end| end <= bytes.len())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn test_class(constants: &[&str], native_method: bool) -> Vec<u8> {
        fn utf8(value: &str) -> Vec<u8> {
            let mut entry = vec![1];
            entry.extend_from_slice(&(value.len() as u16).to_be_bytes());
            entry.extend_from_slice(value.as_bytes());
            entry
        }
        let mut entries = vec![
            utf8("Fixture"),
            vec![7, 0, 1],
            utf8("java/lang/Object"),
            vec![7, 0, 3],
            utf8("nativeMethod"),
            utf8("()V"),
        ];
        entries.extend(constants.iter().map(|value| utf8(value)));
        let mut bytes = b"\xca\xfe\xba\xbe".to_vec();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&61u16.to_be_bytes());
        bytes.extend_from_slice(&((entries.len() + 1) as u16).to_be_bytes());
        for entry in entries {
            bytes.extend_from_slice(&entry);
        }
        bytes.extend_from_slice(&0x0021u16.to_be_bytes()); // public/super
        bytes.extend_from_slice(&2u16.to_be_bytes()); // this class
        bytes.extend_from_slice(&4u16.to_be_bytes()); // superclass
        bytes.extend_from_slice(&0u16.to_be_bytes()); // interfaces
        bytes.extend_from_slice(&0u16.to_be_bytes()); // fields
        bytes.extend_from_slice(&(native_method as u16).to_be_bytes()); // methods
        if native_method {
            bytes.extend_from_slice(&0x0101u16.to_be_bytes()); // public/native
            bytes.extend_from_slice(&5u16.to_be_bytes()); // method name
            bytes.extend_from_slice(&6u16.to_be_bytes()); // descriptor
            bytes.extend_from_slice(&0u16.to_be_bytes()); // attributes
        }
        bytes.extend_from_slice(&0u16.to_be_bytes()); // class attributes
        bytes
    }

    fn test_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, contents) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn valid_java_class_reports_binding_without_claiming_runtime_enforcement() {
        let bytes = test_class(&["SetWindowDisplayAffinity", "com/sun/jna/Library"], false);
        let mut scan = JavaScan::default();
        assert!(inspect_class(
            &bytes,
            "Fixture.class",
            ScanOptions::default(),
            &mut scan
        ));
        assert_eq!(scan.classes, 1);
        assert_eq!(scan.bridge_classes, 1);
        assert!(scan.findings.iter().any(|finding| {
            finding.kind == EvidenceKind::JavaNativeBridge
                && finding.level == RiskLevel::Medium
                && finding.detail.contains("cannot prove the call executes")
        }));
    }

    #[test]
    fn jar_and_nested_jar_classes_are_inspected() {
        let nested_class = test_class(&["SetWindowDisplayAffinity"], true);
        let nested = test_archive(&[("Nested.class", &nested_class)]);
        let outer_class = test_class(&["java/lang/foreign/Linker"], false);
        let outer = test_archive(&[
            ("BOOT-INF/classes/Outer.class", &outer_class),
            ("BOOT-INF/lib/library.jar", &nested),
        ]);
        let mut scan = JavaScan::default();
        inspect_archive(&outer, "jar", 0, "", ScanOptions::default(), &mut scan).unwrap();
        assert_eq!(scan.classes, 2);
        assert_eq!(scan.bridge_classes, 2);
        assert!(scan.findings.iter().any(|finding| {
            finding
                .detail
                .contains("BOOT-INF/lib/library.jar!/Nested.class")
        }));
    }

    #[test]
    fn jmod_header_is_removed_before_zip_parsing() {
        let class = test_class(&[], false);
        let zip = test_archive(&[("classes/Fixture.class", &class)]);
        let mut jmod = b"JM\x01\x00".to_vec();
        jmod.extend_from_slice(&zip);
        let mut scan = JavaScan::default();
        inspect_archive(&jmod, "jmod", 0, "", ScanOptions::default(), &mut scan).unwrap();
        assert_eq!(scan.classes, 1);
    }

    #[test]
    fn malformed_archive_returns_an_error() {
        let path = Path::new("invalid.jar");
        let result = analyze_java_archive(
            path,
            "invalid.jar",
            7,
            "abc".to_owned(),
            b"not-zip",
            ScanOptions::default(),
        );
        assert_eq!(result.highest_level, RiskLevel::Error);
        assert!(result.error.unwrap().contains("archive parsing failed"));
    }

    #[test]
    fn nested_archive_limit_is_visible_in_result() {
        let class = test_class(&[], false);
        let level_four = test_archive(&[("Fixture.class", &class)]);
        let level_three = test_archive(&[("nested.jar", &level_four)]);
        let level_two = test_archive(&[("nested.jar", &level_three)]);
        let level_one = test_archive(&[("nested.jar", &level_two)]);
        let mut scan = JavaScan::default();
        inspect_archive(&level_one, "jar", 0, "", ScanOptions::default(), &mut scan).unwrap();
        let result = scan.finish(
            Path::new("outer.jar"),
            "outer.jar",
            "Java archive (JAR)".to_owned(),
            level_one.len() as u64,
            "abc".to_owned(),
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.title == "Java archive inspection incomplete")
        );
    }

    #[test]
    fn oversized_archive_member_produces_partial_scan_evidence() {
        let oversized = vec![0u8; MAX_ENTRY_BYTES as usize + 1];
        let archive = test_archive(&[("Large.class", &oversized)]);
        let mut scan = JavaScan::default();
        inspect_archive(&archive, "jar", 0, "", ScanOptions::default(), &mut scan).unwrap();
        let result = scan.finish(
            Path::new("large.jar"),
            "large.jar",
            "Java archive (JAR)".to_owned(),
            archive.len() as u64,
            "abc".to_owned(),
        );
        assert_eq!(scan_warning_count(&result), 1);
        assert_eq!(result.architecture, "Unknown");
    }

    fn scan_warning_count(result: &ScanResult) -> usize {
        result
            .findings
            .iter()
            .filter(|finding| finding.title == "Java archive inspection incomplete")
            .count()
    }

    #[test]
    fn java_toggle_filters_folder_candidates() {
        let disabled = ScanOptions {
            java: false,
            ..ScanOptions::default()
        };
        assert!(!is_candidate(Path::new("a.jar"), disabled));
        assert!(!is_candidate(Path::new("a.class"), disabled));
        assert!(is_candidate(Path::new("a.dll"), disabled));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn jar_inspects_bundled_pe_imports() {
        use std::process::Command;

        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("wda_fixture.rs");
        let output = std::env::temp_dir().join(format!(
            "ororesea-java-native-fixture-{}.exe",
            std::process::id()
        ));
        let status = Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&output)
            .status()
            .expect("rustc should compile the native fixture");
        assert!(status.success());
        let pe_bytes = fs::read(&output).unwrap();
        let _ = fs::remove_file(&output);
        assert!(pe_bytes.len() as u64 <= MAX_ENTRY_BYTES);
        let jar = test_archive(&[("natives/wda.exe", &pe_bytes)]);
        let mut scan = JavaScan::default();
        inspect_archive(&jar, "jar", 0, "", ScanOptions::default(), &mut scan).unwrap();
        assert_eq!(scan.native_images, 1);
        assert!(scan.findings.iter().any(|finding| {
            finding.kind == EvidenceKind::DirectImport && finding.detail.contains("natives/wda.exe")
        }));
    }

    #[test]
    fn direct_set_import_is_high_confidence() {
        let imports = vec![ParsedImport {
            dll: "USER32.dll".to_owned(),
            name: "SetWindowDisplayAffinity".to_owned(),
            delayed: false,
        }];
        let findings = classify_evidence(&imports, b"", false);
        assert_eq!(findings[0].level, RiskLevel::High);
        assert_eq!(findings[0].confidence, 95);
    }

    #[test]
    fn get_api_alone_is_informational() {
        let imports = vec![ParsedImport {
            dll: "USER32.dll".to_owned(),
            name: "GetWindowDisplayAffinity".to_owned(),
            delayed: false,
        }];
        let findings = classify_evidence(&imports, b"", false);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].level, RiskLevel::Informational);
    }

    #[test]
    fn dynamic_resolution_pattern_is_medium() {
        let imports = vec![ParsedImport {
            dll: "KERNEL32.dll".to_owned(),
            name: "GetProcAddress".to_owned(),
            delayed: false,
        }];
        let findings = classify_evidence(
            &imports,
            b"SetWindowDisplayAffinity\0GetProcAddress\0",
            false,
        );
        assert_eq!(findings[0].level, RiskLevel::Medium);
    }

    #[test]
    fn detects_utf16_api_name() {
        let bytes: Vec<u8> = "SetWindowDisplayAffinity"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(contains_text_ci(&bytes, "setwindowdisplayaffinity"));
    }

    #[test]
    fn mitigation_import_is_capability_not_active_cig() {
        let imports = vec![ParsedImport {
            dll: "KERNEL32.dll".to_owned(),
            name: "SetProcessMitigationPolicy".to_owned(),
            delayed: false,
        }];
        let findings = classify_evidence_with_options(
            &imports,
            b"ProcessSignaturePolicy\0",
            false,
            ScanOptions {
                wda: false,
                process_mitigations: true,
                dll_loading: false,
                java: true,
            },
        );
        assert!(findings.iter().any(|finding| {
            finding.kind == EvidenceKind::MitigationApi
                && finding.title == "Process-mitigation setter capability"
                && finding.level == RiskLevel::Informational
        }));
        assert!(findings.iter().any(|finding| {
            finding.title == "Probable binary-signature/CIG policy capability"
                && finding
                    .detail
                    .contains("requires GetProcessMitigationPolicy readback")
        }));
    }

    #[test]
    fn scan_options_keep_capability_families_independent() {
        let imports = vec![
            ParsedImport {
                dll: "USER32.dll".to_owned(),
                name: "SetWindowDisplayAffinity".to_owned(),
                delayed: false,
            },
            ParsedImport {
                dll: "KERNEL32.dll".to_owned(),
                name: "SetDefaultDllDirectories".to_owned(),
                delayed: false,
            },
        ];
        let findings = classify_evidence_with_options(
            &imports,
            b"",
            false,
            ScanOptions {
                wda: false,
                process_mitigations: false,
                dll_loading: true,
                java: true,
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, EvidenceKind::DllSearchHardening);
        assert_eq!(findings[0].level, RiskLevel::Informational);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn analyzes_a_real_pe_import_fixture() {
        use std::process::Command;

        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("wda_fixture.rs");
        let output =
            std::env::temp_dir().join(format!("ororesea-wda-fixture-{}.exe", std::process::id()));
        let status = Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&output)
            .status()
            .expect("rustc should compile the fixture");
        assert!(status.success());

        let result = analyze_file(&output);
        let _ = fs::remove_file(&output);
        assert_eq!(result.highest_level, RiskLevel::High);
        assert!(
            result
                .relevant_imports
                .iter()
                .any(|import| import.contains("SetWindowDisplayAffinity"))
        );

        let delay_output = std::env::temp_dir().join(format!(
            "ororesea-wda-delay-fixture-{}.exe",
            std::process::id()
        ));
        let delay_status = Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&delay_output)
            .arg("-C")
            .arg("link-arg=/DELAYLOAD:user32.dll")
            .arg("-C")
            .arg("link-arg=delayimp.lib")
            .status()
            .expect("rustc should compile the delay-load fixture");
        assert!(delay_status.success());

        let delay_result = analyze_file(&delay_output);
        let _ = fs::remove_file(&delay_output);
        assert_eq!(delay_result.highest_level, RiskLevel::High);
        assert!(
            delay_result.findings[0]
                .title
                .starts_with("Delay-loaded SetWindowDisplayAffinity")
        );
    }
}
