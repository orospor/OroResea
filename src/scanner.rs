use crate::model::{Evidence, EvidenceKind, RiskLevel, ScanResult};
use goblin::Object;
use sha2::{Digest, Sha256};
use std::{
    fs,
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

const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
const TARGET_EXTENSIONS: &[&str] = &["exe", "dll", "node", "ocx", "cpl", "scr", "sys"];

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

pub fn spawn_scan(root: PathBuf) -> (Receiver<ScanMessage>, Arc<AtomicBool>) {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);

    thread::spawn(move || run_scan(root, tx, worker_cancel));
    (rx, cancel)
}

fn run_scan(root: PathBuf, tx: Sender<ScanMessage>, cancel: Arc<AtomicBool>) {
    let started = Instant::now();
    let candidates = collect_candidates(&root);
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

        let result = analyze_file(&path);
        if tx.send(ScanMessage::Result(result)).is_err() {
            return;
        }
    }

    let _ = tx.send(ScanMessage::Finished {
        cancelled: false,
        elapsed: started.elapsed(),
    });
}

fn collect_candidates(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_owned()];
    }

    let mut paths: Vec<PathBuf> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| is_candidate(path))
        .collect();

    paths.sort_by_cached_key(|path| path.to_string_lossy().to_ascii_lowercase());
    paths
}

fn is_candidate(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| TARGET_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

pub fn analyze_file(path: &Path) -> ScanResult {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return ScanResult::failed(path.to_owned(), error.to_string()),
    };

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
    let findings = classify_evidence(&imports, &bytes, is_managed);
    let highest_level = findings
        .iter()
        .map(|finding| finding.level)
        .max_by_key(|level| level.rank())
        .unwrap_or(RiskLevel::Clean);

    let relevant_imports = imports
        .iter()
        .filter(|import| {
            import.name.eq_ignore_ascii_case("SetWindowDisplayAffinity")
                || import.name.eq_ignore_ascii_case("GetWindowDisplayAffinity")
                || import.name.eq_ignore_ascii_case("GetProcAddress")
                || import.name.to_ascii_lowercase().starts_with("loadlibrary")
        })
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

fn classify_evidence(imports: &[ParsedImport], bytes: &[u8], is_managed: bool) -> Vec<Evidence> {
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

    let mut findings = Vec::new();

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

    findings.sort_by_key(|finding| std::cmp::Reverse(finding.level.rank()));
    findings
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
