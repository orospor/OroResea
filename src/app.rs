use crate::{
    live_posture::ProcessSummary,
    model::{
        AssessmentProfile, AuditScope, OroNimbusCigExpectation, OroNimbusProfile,
        OroNimbusWdaExpectation, PostureAssessment, PostureCheck, PostureVerdict, ReportSummary,
        RiskLevel, ScanResult,
    },
    posture::{self, PostureMessage},
    report,
    scanner::{self, ScanMessage, ScanOptions},
};
use eframe::egui::{
    self, Align, Color32, FontId, Layout, ProgressBar, RichText, ScrollArea, Sense, Stroke,
    TextEdit, Vec2,
};
use rfd::FileDialog;
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::Receiver,
    },
    time::Duration,
};

const GOLD: Color32 = Color32::from_rgb(218, 177, 83);
const TEXT: Color32 = Color32::from_rgb(230, 236, 244);
const MUTED: Color32 = Color32::from_rgb(143, 158, 174);
const PANEL: Color32 = Color32::from_rgb(16, 22, 30);
const PANEL_ALT: Color32 = Color32::from_rgb(20, 28, 38);
const BORDER: Color32 = Color32::from_rgb(40, 52, 65);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppMode {
    WdaEvidence,
    ProtectionPosture,
}

pub struct OroReseaApp {
    mode: AppMode,
    source_text: String,
    results: Vec<ScanResult>,
    selected: Option<usize>,
    query: String,
    only_flagged: bool,
    scan_wda: bool,
    scan_process_mitigations: bool,
    scan_dll_loading: bool,
    scan_rx: Option<Receiver<ScanMessage>>,
    cancel: Option<Arc<AtomicBool>>,
    scanning: bool,
    progress_current: usize,
    progress_total: usize,
    current_file: String,
    last_elapsed: Option<Duration>,
    status: String,
    posture_source_text: String,
    posture_processes: Vec<ProcessSummary>,
    posture_selected_pid: Option<u32>,
    posture_query: String,
    posture_visible_only: bool,
    posture_profile: AssessmentProfile,
    posture_rx: Option<Receiver<PostureMessage>>,
    posture_assessment: Option<PostureAssessment>,
    posture_busy: bool,
    posture_status: String,
    show_methodology: bool,
}

impl OroReseaApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);
        Self {
            mode: AppMode::WdaEvidence,
            source_text: String::new(),
            results: Vec::new(),
            selected: None,
            query: String::new(),
            only_flagged: false,
            scan_wda: true,
            scan_process_mitigations: true,
            scan_dll_loading: true,
            scan_rx: None,
            cancel: None,
            scanning: false,
            progress_current: 0,
            progress_total: 0,
            current_file: String::new(),
            last_elapsed: None,
            status: "Choose a Windows binary or a directory to begin.".to_owned(),
            posture_source_text: String::new(),
            posture_processes: Vec::new(),
            posture_selected_pid: None,
            posture_query: String::new(),
            posture_visible_only: false,
            posture_profile: AssessmentProfile::Generic,
            posture_rx: None,
            posture_assessment: None,
            posture_busy: false,
            posture_status:
                "Choose a file for pre-launch checks or refresh the live process inventory."
                    .to_owned(),
            show_methodology: false,
        }
    }

    fn begin_scan(&mut self) {
        let source = PathBuf::from(self.source_text.trim());
        if self.source_text.trim().is_empty() {
            self.status = "Choose a file or directory first.".to_owned();
            return;
        }
        if !source.exists() {
            self.status = "The selected path does not exist.".to_owned();
            return;
        }

        if !self.scan_wda && !self.scan_process_mitigations && !self.scan_dll_loading {
            self.status = "Select at least one static scan category.".to_owned();
            return;
        }

        let (rx, cancel) = scanner::spawn_scan_with_options(
            source,
            ScanOptions {
                wda: self.scan_wda,
                process_mitigations: self.scan_process_mitigations,
                dll_loading: self.scan_dll_loading,
            },
        );
        self.results.clear();
        self.selected = None;
        self.scan_rx = Some(rx);
        self.cancel = Some(cancel);
        self.scanning = true;
        self.progress_current = 0;
        self.progress_total = 0;
        self.current_file.clear();
        self.last_elapsed = None;
        self.status = "Discovering candidate PE files...".to_owned();
    }

    fn cancel_scan(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
            self.status = "Cancellation requested...".to_owned();
        }
    }

    fn poll_scan(&mut self) {
        let messages: Vec<ScanMessage> = self
            .scan_rx
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        let mut finished = false;

        for message in messages {
            match message {
                ScanMessage::Started { total } => {
                    self.progress_total = total;
                    self.status = if total == 0 {
                        "No supported PE file extensions were found.".to_owned()
                    } else {
                        format!("Found {total} candidate file(s).")
                    };
                }
                ScanMessage::Progress {
                    current,
                    total,
                    path,
                } => {
                    self.progress_current = current;
                    self.progress_total = total;
                    self.current_file = path.to_string_lossy().into_owned();
                }
                ScanMessage::Result(result) => self.results.push(result),
                ScanMessage::Finished { cancelled, elapsed } => {
                    self.scanning = false;
                    self.last_elapsed = Some(elapsed);
                    self.current_file.clear();
                    self.results.sort_by(|left, right| {
                        right
                            .highest_level
                            .rank()
                            .cmp(&left.highest_level.rank())
                            .then_with(|| {
                                left.path
                                    .to_string_lossy()
                                    .to_ascii_lowercase()
                                    .cmp(&right.path.to_string_lossy().to_ascii_lowercase())
                            })
                    });
                    self.status = if cancelled {
                        format!("Scan cancelled after {} file(s).", self.results.len())
                    } else {
                        format!(
                            "Scan complete: {} file(s) in {:.2}s.",
                            self.results.len(),
                            elapsed.as_secs_f32()
                        )
                    };
                    finished = true;
                }
            }
        }

        if finished {
            self.scan_rx = None;
            self.cancel = None;
        }
    }

    fn refresh_processes(&mut self) {
        self.posture_status = if self.posture_visible_only {
            "Refreshing processes with a top-level window...".to_owned()
        } else {
            "Refreshing the complete process inventory...".to_owned()
        };
        match posture::enumerate_processes(self.posture_visible_only) {
            Ok(processes) => {
                let previous_selection = self.posture_selected_pid;
                self.posture_processes = processes;
                self.posture_selected_pid = previous_selection.filter(|pid| {
                    self.posture_processes
                        .iter()
                        .any(|process| process.pid == *pid)
                });
                self.posture_status = format!(
                    "Loaded {} process(es). Select one for a read-only snapshot.",
                    self.posture_processes.len()
                );
            }
            Err(error) => {
                self.posture_processes.clear();
                self.posture_selected_pid = None;
                self.posture_status = format!("Could not enumerate processes: {error}");
            }
        }
    }

    fn begin_file_posture(&mut self) {
        let source = PathBuf::from(self.posture_source_text.trim());
        if self.posture_source_text.trim().is_empty() {
            self.posture_status = "Choose an EXE or DLL first.".to_owned();
            return;
        }
        if !source.is_file() {
            self.posture_status =
                "The selected path must be an existing Windows binary file.".to_owned();
            return;
        }

        self.posture_rx = Some(posture::spawn_file_assessment_with_profile(
            source.clone(),
            self.posture_profile,
        ));
        self.posture_busy = true;
        self.posture_status = format!(
            "Reading static mitigations and Authenticode trust for {}...",
            source
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("selected file")
        );
    }

    fn begin_process_posture(&mut self) {
        let Some(pid) = self.posture_selected_pid else {
            self.posture_status = "Select a running process first.".to_owned();
            return;
        };
        let name = self
            .posture_processes
            .iter()
            .find(|process| process.pid == pid)
            .map(|process| process.executable_name.as_str())
            .unwrap_or("selected process");
        self.posture_rx = Some(posture::spawn_process_assessment_with_profile(
            pid,
            self.posture_profile,
        ));
        self.posture_busy = true;
        self.posture_status = format!("Capturing read-only posture for {name} (PID {pid})...");
    }

    fn poll_posture(&mut self) {
        let messages: Vec<PostureMessage> = self
            .posture_rx
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();

        for message in messages {
            let PostureMessage::Finished(assessment) = message;
            let summary = assessment.summary();
            let target = posture_target_label(&assessment);
            self.posture_status = format!(
                "Snapshot complete for {target}: {} pass, {} fail, {} warning, {} unavailable.",
                summary.pass, summary.fail, summary.warning, summary.unavailable
            );
            self.posture_assessment = Some(assessment);
            self.posture_busy = false;
            self.posture_rx = None;
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|input| input.raw.dropped_files.clone());
        if let Some(path) = dropped.first().map(|file| file.path().to_owned()) {
            match self.mode {
                AppMode::WdaEvidence => {
                    self.source_text = path.to_string_lossy().into_owned();
                    self.status = "Dropped target selected. Press Scan to analyze it.".to_owned();
                }
                AppMode::ProtectionPosture => {
                    self.posture_source_text = path.to_string_lossy().into_owned();
                    self.posture_status =
                        "Dropped file selected. Press Analyze file for pre-launch checks."
                            .to_owned();
                }
            }
        }
    }

    fn export_json(&mut self) {
        match self.mode {
            AppMode::WdaEvidence => {
                if self.results.is_empty() {
                    self.status = "There are no results to export.".to_owned();
                    return;
                }
                if let Some(path) = FileDialog::new()
                    .set_file_name("OroResea-static-capability-report.json")
                    .add_filter("JSON report", &["json"])
                    .save_file()
                {
                    self.status = match report::write_json(&path, &self.source_text, &self.results)
                    {
                        Ok(()) => format!("JSON report saved to {}", path.display()),
                        Err(error) => format!("Could not export JSON: {error}"),
                    };
                }
            }
            AppMode::ProtectionPosture => {
                let Some(assessment) = self.posture_assessment.as_ref() else {
                    self.posture_status = "There is no posture snapshot to export.".to_owned();
                    return;
                };
                if let Some(path) = FileDialog::new()
                    .set_file_name("OroResea-protection-posture.json")
                    .add_filter("JSON report", &["json"])
                    .save_file()
                {
                    self.posture_status = match report::write_posture_json(&path, assessment) {
                        Ok(()) => format!("JSON posture report saved to {}", path.display()),
                        Err(error) => format!("Could not export posture JSON: {error}"),
                    };
                }
            }
        }
    }

    fn export_csv(&mut self) {
        match self.mode {
            AppMode::WdaEvidence => {
                if self.results.is_empty() {
                    self.status = "There are no results to export.".to_owned();
                    return;
                }
                if let Some(path) = FileDialog::new()
                    .set_file_name("OroResea-static-capability-report.csv")
                    .add_filter("CSV report", &["csv"])
                    .save_file()
                {
                    self.status = match report::write_csv(&path, &self.results) {
                        Ok(()) => format!("CSV report saved to {}", path.display()),
                        Err(error) => format!("Could not export CSV: {error}"),
                    };
                }
            }
            AppMode::ProtectionPosture => {
                let Some(assessment) = self.posture_assessment.as_ref() else {
                    self.posture_status = "There is no posture snapshot to export.".to_owned();
                    return;
                };
                if let Some(path) = FileDialog::new()
                    .set_file_name("OroResea-protection-posture.csv")
                    .add_filter("CSV report", &["csv"])
                    .save_file()
                {
                    self.posture_status = match report::write_posture_csv(&path, assessment) {
                        Ok(()) => format!("CSV posture report saved to {}", path.display()),
                        Err(error) => format!("Could not export posture CSV: {error}"),
                    };
                }
            }
        }
    }

    fn export_html(&mut self) {
        match self.mode {
            AppMode::WdaEvidence => {
                if self.results.is_empty() {
                    self.status = "There are no results to export.".to_owned();
                    return;
                }
                if let Some(path) = FileDialog::new()
                    .set_file_name("OroResea-static-capability-report.html")
                    .add_filter("HTML report", &["html"])
                    .save_file()
                {
                    self.status = match report::write_html(&path, &self.source_text, &self.results)
                    {
                        Ok(()) => format!("HTML report saved to {}", path.display()),
                        Err(error) => format!("Could not export HTML: {error}"),
                    };
                }
            }
            AppMode::ProtectionPosture => {
                let Some(assessment) = self.posture_assessment.as_ref() else {
                    self.posture_status = "There is no posture snapshot to export.".to_owned();
                    return;
                };
                if let Some(path) = FileDialog::new()
                    .set_file_name("OroResea-protection-posture.html")
                    .add_filter("HTML report", &["html"])
                    .save_file()
                {
                    self.posture_status = match report::write_posture_html(&path, assessment) {
                        Ok(()) => format!("HTML posture report saved to {}", path.display()),
                        Err(error) => format!("Could not export posture HTML: {error}"),
                    };
                }
            }
        }
    }

    fn has_active_export(&self) -> bool {
        match self.mode {
            AppMode::WdaEvidence => !self.results.is_empty(),
            AppMode::ProtectionPosture => self.posture_assessment.is_some(),
        }
    }

    fn show_header(&mut self, root: &mut egui::Ui) {
        egui::Panel::top("header")
            .frame(
                egui::Frame::NONE
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(20, 14)),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
                    ui.painter()
                        .rect(rect, 11.0, GOLD, Stroke::NONE, egui::StrokeKind::Inside);
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "OR",
                        FontId::proportional(17.0),
                        Color32::from_rgb(18, 20, 22),
                    );
                    ui.vertical(|ui| {
                        ui.label(RichText::new("OroResea").size(22.0).strong().color(TEXT));
                        ui.label(
                            RichText::new(
                                "Windows capture-protection capability and process-posture analyzer",
                            )
                                .size(12.0)
                                .color(MUTED),
                        );
                    });
                    ui.add_space((ui.available_width() - 205.0).max(8.0));
                    if ui.button("Methodology").clicked() {
                        self.show_methodology = true;
                    }
                    ui.menu_button("Export", |ui| {
                        ui.add_enabled_ui(self.has_active_export(), |ui| {
                            if ui.button("JSON report").clicked() {
                                ui.close();
                                self.export_json();
                            }
                            if ui.button("CSV report").clicked() {
                                ui.close();
                                self.export_csv();
                            }
                            if ui.button("HTML report").clicked() {
                                ui.close();
                                self.export_html();
                            }
                        });
                    });
                });
            });
    }

    fn show_mode_tabs(&mut self, root: &mut egui::Ui) {
        let mut refresh_on_switch = false;
        egui::Panel::top("mode_tabs")
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(9, 13, 18))
                    .inner_margin(egui::Margin::symmetric(20, 8)),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("ANALYSIS MODE")
                            .size(10.0)
                            .strong()
                            .color(MUTED),
                    );
                    let wda = ui.selectable_label(
                        self.mode == AppMode::WdaEvidence,
                        RichText::new("Static Capabilities").strong(),
                    );
                    if wda.clicked() {
                        self.mode = AppMode::WdaEvidence;
                    }
                    let posture = ui.selectable_label(
                        self.mode == AppMode::ProtectionPosture,
                        RichText::new("Protection Posture").strong(),
                    );
                    if posture.clicked() {
                        let switching = self.mode != AppMode::ProtectionPosture;
                        self.mode = AppMode::ProtectionPosture;
                        refresh_on_switch = switching && self.posture_processes.is_empty();
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let text = match self.mode {
                            AppMode::WdaEvidence => "STATIC • NEVER EXECUTES TARGETS",
                            AppMode::ProtectionPosture => {
                                "STATIC + LIVE SNAPSHOT • READ-ONLY METADATA"
                            }
                        };
                        ui.label(RichText::new(text).size(10.0).strong().color(GOLD));
                    });
                });
            });
        if refresh_on_switch {
            self.refresh_processes();
        }
    }

    fn show_target_panel(&mut self, root: &mut egui::Ui) {
        egui::Panel::top("target")
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(12, 17, 23))
                    .inner_margin(egui::Margin::symmetric(20, 13)),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("TARGET").size(11.0).strong().color(GOLD));
                    let width = (ui.available_width() - 245.0).max(160.0);
                    ui.add(
                        TextEdit::singleline(&mut self.source_text)
                            .desired_width(width)
                            .hint_text("Drop or choose an EXE, DLL, or directory"),
                    );
                    if ui.button("File...").clicked()
                        && let Some(path) = FileDialog::new()
                            .add_filter(
                                "Windows binaries",
                                &["exe", "dll", "node", "ocx", "cpl", "scr", "sys"],
                            )
                            .pick_file()
                    {
                        self.source_text = path.to_string_lossy().into_owned();
                    }
                    if ui.button("Folder...").clicked()
                        && let Some(path) = FileDialog::new().pick_folder()
                    {
                        self.source_text = path.to_string_lossy().into_owned();
                    }
                    if self.scanning {
                        if ui.button("Cancel").clicked() {
                            self.cancel_scan();
                        }
                    } else if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Scan")
                                    .strong()
                                    .color(Color32::from_rgb(18, 20, 22)),
                            )
                            .fill(GOLD),
                        )
                        .clicked()
                    {
                        self.begin_scan();
                    }
                });

                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("SCAN FOR").size(10.0).strong().color(GOLD));
                    ui.checkbox(&mut self.scan_wda, "WDA APIs and markers")
                        .on_hover_text(
                            "Set/GetWindowDisplayAffinity imports, dynamic bindings, strings, and named WDA markers.",
                        );
                    ui.checkbox(
                        &mut self.scan_process_mitigations,
                        "CIG / mitigation APIs",
                    )
                    .on_hover_text(
                        "Set/GetProcessMitigationPolicy and signature-policy markers. Static evidence is capability only; live readback is required for effective CIG.",
                    );
                    ui.checkbox(&mut self.scan_dll_loading, "DLL search / loading APIs")
                        .on_hover_text(
                            "SetDefaultDllDirectories, SetDllDirectoryW, AddDllDirectory, and LoadLibrary variants.",
                        );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new("CAPABILITY SCAN • DOES NOT EXECUTE FILES")
                                .size(9.5)
                                .strong()
                                .color(MUTED),
                        );
                    });
                });

                if self.scanning {
                    ui.add_space(7.0);
                    let fraction = if self.progress_total == 0 {
                        0.0
                    } else {
                        self.progress_current as f32 / self.progress_total as f32
                    };
                    ui.add(ProgressBar::new(fraction).show_percentage().text(format!(
                        "{} / {}  {}",
                        self.progress_current,
                        self.progress_total,
                        truncate_middle(&self.current_file, 95)
                    )));
                }
            });
    }

    fn show_posture_target_panel(&mut self, root: &mut egui::Ui) {
        let mut refresh_for_filter_change = false;
        let mut profile_changed = false;
        egui::Panel::top("posture_target")
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(12, 17, 23))
                    .inner_margin(egui::Margin::symmetric(20, 12)),
            )
            .show(root, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("PROFILE").size(10.0).strong().color(GOLD));
                    if ui
                        .selectable_label(
                            self.posture_profile == AssessmentProfile::Generic,
                            "Generic posture",
                        )
                        .clicked()
                    {
                        profile_changed = self.posture_profile != AssessmentProfile::Generic;
                        self.posture_profile = AssessmentProfile::Generic;
                    }
                    let using_oronimbus =
                        matches!(self.posture_profile, AssessmentProfile::OroNimbus(_));
                    if ui
                        .selectable_label(using_oronimbus, "OroNimbus lab")
                        .on_hover_text(
                            "Correlate exact WDA and MicrosoftSignedOnly CIG expectations against the selected PID. This does not trust the process name alone.",
                        )
                        .clicked()
                        && !using_oronimbus
                    {
                        self.posture_profile =
                            AssessmentProfile::OroNimbus(OroNimbusProfile::default());
                        self.posture_query = "oronimbus".to_owned();
                        profile_changed = true;
                    }

                    if let AssessmentProfile::OroNimbus(mut profile) = self.posture_profile {
                        ui.separator();
                        ui.label(RichText::new("Expected WDA").size(10.0).color(MUTED));
                        egui::ComboBox::from_id_salt("oronimbus_expected_wda")
                            .selected_text(profile.expected_wda.label())
                            .show_ui(ui, |ui| {
                                for value in [
                                    OroNimbusWdaExpectation::ObserveOnly,
                                    OroNimbusWdaExpectation::None,
                                    OroNimbusWdaExpectation::Monitor,
                                    OroNimbusWdaExpectation::ExcludeFromCapture,
                                ] {
                                    ui.selectable_value(
                                        &mut profile.expected_wda,
                                        value,
                                        value.label(),
                                    );
                                }
                            });
                        ui.label(RichText::new("Expected CIG").size(10.0).color(MUTED));
                        egui::ComboBox::from_id_salt("oronimbus_expected_cig")
                            .selected_text(profile.expected_cig.label())
                            .show_ui(ui, |ui| {
                                for value in [
                                    OroNimbusCigExpectation::ObserveOnly,
                                    OroNimbusCigExpectation::Disabled,
                                    OroNimbusCigExpectation::MicrosoftSignedOnly,
                                ] {
                                    ui.selectable_value(
                                        &mut profile.expected_cig,
                                        value,
                                        value.label(),
                                    );
                                }
                            });
                        if self.posture_profile != AssessmentProfile::OroNimbus(profile) {
                            profile_changed = true;
                        }
                        self.posture_profile = AssessmentProfile::OroNimbus(profile);
                        if ui
                            .button("Find OroNimbus")
                            .on_hover_text(
                                "Refresh all processes and apply an OroNimbus text filter. Select the PID that owns the visible browser window.",
                            )
                            .clicked()
                        {
                            self.posture_query = "oronimbus".to_owned();
                            self.posture_visible_only = false;
                            refresh_for_filter_change = true;
                        }
                    }
                });
                ui.add_space(3.0);

                ui.horizontal(|ui| {
                    ui.label(RichText::new("STATIC FILE").size(10.0).strong().color(GOLD));
                    let width = (ui.available_width() - 245.0).max(180.0);
                    ui.add(
                        TextEdit::singleline(&mut self.posture_source_text)
                            .desired_width(width)
                            .hint_text("Choose or drop an EXE or DLL for pre-launch checks"),
                    );
                    if ui
                        .add_enabled(!self.posture_busy, egui::Button::new("File..."))
                        .clicked()
                        && let Some(path) = FileDialog::new()
                            .add_filter(
                                "Windows binaries",
                                &["exe", "dll", "node", "ocx", "cpl", "scr", "sys"],
                            )
                            .pick_file()
                    {
                        self.posture_source_text = path.to_string_lossy().into_owned();
                        self.posture_status =
                            "File selected. Analyze reads it as data and does not launch it."
                                .to_owned();
                    }
                    if ui
                        .add_enabled(
                            !self.posture_busy,
                            egui::Button::new(
                                RichText::new("Analyze file")
                                    .strong()
                                    .color(Color32::from_rgb(18, 20, 22)),
                            )
                            .fill(GOLD),
                        )
                        .clicked()
                    {
                        self.begin_file_posture();
                    }
                });

                ui.add_space(3.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("LIVE PROCESS").size(10.0).strong().color(GOLD));
                    ui.add(
                        TextEdit::singleline(&mut self.posture_query)
                            .desired_width(310.0)
                            .hint_text("Filter by process, PID, or path"),
                    );
                    if ui
                        .checkbox(&mut self.posture_visible_only, "Top-level windows only")
                        .on_hover_text(
                            "Limit the inventory to processes that currently own a top-level window.",
                        )
                        .changed()
                    {
                        refresh_for_filter_change = true;
                    }
                    if ui
                        .add_enabled(!self.posture_busy, egui::Button::new("Refresh"))
                        .clicked()
                    {
                        self.refresh_processes();
                    }
                    let snapshot = ui.add_enabled(
                        !self.posture_busy && self.posture_selected_pid.is_some(),
                        egui::Button::new(
                            RichText::new("Snapshot selected")
                                .strong()
                                .color(Color32::from_rgb(18, 20, 22)),
                        )
                        .fill(GOLD),
                    );
                    if snapshot.clicked() {
                        self.begin_process_posture();
                    }
                    if self.posture_busy {
                        ui.spinner();
                    }
                });
            });

        if refresh_for_filter_change {
            self.refresh_processes();
        }
        if profile_changed {
            self.posture_assessment = None;
            self.posture_status = match self.posture_profile {
                AssessmentProfile::Generic => {
                    "Generic posture profile selected. Choose a file or process.".to_owned()
                }
                AssessmentProfile::OroNimbus(profile) => format!(
                    "OroNimbus profile selected: WDA {}, CIG {}. Select the main/WDA-owner PID and snapshot it.",
                    profile.expected_wda.label(),
                    profile.expected_cig.label()
                ),
            };
        }
    }

    fn show_posture_workspace(&mut self, root: &mut egui::Ui) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(10, 14, 19))
                    .inner_margin(egui::Margin::symmetric(20, 13)),
            )
            .show(root, |ui| {
                if let Some(assessment) = &self.posture_assessment {
                    show_posture_summary(ui, assessment);
                    ui.add_space(10.0);
                }

                egui::Frame::NONE
                    .fill(Color32::from_rgb(12, 18, 24))
                    .stroke(Stroke::new(1.0, BORDER))
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::symmetric(11, 8))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            if self.posture_busy {
                                ui.spinner();
                            }
                            ui.label(
                                RichText::new(&self.posture_status)
                                    .size(12.0)
                                    .color(if self.posture_busy { GOLD } else { MUTED }),
                            );
                        });
                    });
                ui.add_space(10.0);

                ui.columns(2, |columns| {
                    self.show_process_picker(&mut columns[0]);
                    self.show_posture_assessment(&mut columns[1]);
                });
            });
    }

    fn show_process_picker(&mut self, ui: &mut egui::Ui) {
        egui::Frame::NONE
            .fill(PANEL)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(10.0)
            .inner_margin(egui::Margin::symmetric(11, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("RUNNING PROCESSES").size(11.0).strong().color(GOLD));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{} loaded", self.posture_processes.len()))
                                .size(11.0)
                                .color(MUTED),
                        );
                    });
                });
                ui.label(
                    RichText::new(
                        "Administrator access can improve coverage; denied metadata stays unavailable.",
                    )
                    .size(11.0)
                    .color(MUTED),
                );
                ui.add_space(5.0);

                let query = self.posture_query.trim().to_ascii_lowercase();
                let visible: Vec<usize> = self
                    .posture_processes
                    .iter()
                    .enumerate()
                    .filter(|(_, process)| process_matches(process, &query))
                    .map(|(index, _)| index)
                    .collect();

                if self.posture_processes.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(44.0);
                        ui.label(RichText::new("No process inventory loaded").color(TEXT));
                        ui.label(
                            RichText::new("Use Refresh above to enumerate running processes.")
                                .size(11.0)
                                .color(MUTED),
                        );
                        ui.add_space(44.0);
                    });
                } else if visible.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(44.0);
                        ui.label(RichText::new("No process matches this filter.").color(MUTED));
                        ui.add_space(44.0);
                    });
                } else {
                    ScrollArea::vertical()
                        .id_salt("posture_processes")
                        .auto_shrink([false, false])
                        .max_height(ui.available_height())
                        .show(ui, |ui| {
                            for index in visible {
                                let process = &self.posture_processes[index];
                                let pid = process.pid;
                                let response = draw_process_row(
                                    ui,
                                    process,
                                    self.posture_selected_pid == Some(pid),
                                );
                                if response.clicked() {
                                    self.posture_selected_pid = Some(pid);
                                    self.posture_status = format!(
                                        "Selected {} (PID {pid}). Press Snapshot selected.",
                                        process.executable_name
                                    );
                                }
                            }
                        });
                }
            });
    }

    fn show_posture_assessment(&self, ui: &mut egui::Ui) {
        egui::Frame::NONE
            .fill(PANEL)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(10.0)
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                let Some(assessment) = &self.posture_assessment else {
                    ui.label(
                        RichText::new("PROTECTION POSTURE")
                            .size(11.0)
                            .strong()
                            .color(GOLD),
                    );
                    ui.vertical_centered(|ui| {
                        ui.add_space(55.0);
                        ui.label(
                            RichText::new("No posture snapshot yet")
                                .size(18.0)
                                .color(TEXT),
                        );
                        ui.label(
                            RichText::new(
                                "Analyze a file, or select a live process and capture a snapshot.",
                            )
                            .size(11.0)
                            .color(MUTED),
                        );
                        ui.add_space(55.0);
                    });
                    return;
                };

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(posture_target_label(assessment))
                                .size(17.0)
                                .strong()
                                .color(TEXT),
                        );
                        let subtitle = posture_target_subtitle(assessment);
                        ui.label(RichText::new(subtitle).size(11.0).color(MUTED));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if let Some(path) = assessment.target.path.as_deref()
                            && ui.small_button("Open location").clicked()
                        {
                            reveal_in_explorer(path);
                        }
                    });
                });
                ui.add_space(7.0);

                ScrollArea::vertical()
                    .id_salt("posture_assessment")
                    .auto_shrink([false, false])
                    .max_height(ui.available_height())
                    .show(ui, |ui| {
                        for scope in [
                            AuditScope::Profile,
                            AuditScope::Static,
                            AuditScope::Live,
                            AuditScope::System,
                        ] {
                            let checks: Vec<&PostureCheck> = assessment
                                .checks
                                .iter()
                                .filter(|check| check.scope == scope)
                                .collect();
                            if checks.is_empty() {
                                continue;
                            }
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("{} CHECKS", scope.label()))
                                        .size(10.0)
                                        .strong()
                                        .color(GOLD),
                                );
                                ui.label(
                                    RichText::new(format!("{} item(s)", checks.len()))
                                        .size(10.0)
                                        .color(MUTED),
                                );
                            });
                            ui.add_space(3.0);
                            for check in checks {
                                posture_check_box(ui, check);
                            }
                            ui.add_space(5.0);
                        }

                        if !assessment.limitations.is_empty() {
                            ui.separator();
                            ui.label(RichText::new("LIMITATIONS").size(10.0).strong().color(GOLD));
                            for limitation in &assessment.limitations {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(RichText::new("•").color(GOLD));
                                    ui.label(RichText::new(limitation).size(11.0).color(MUTED));
                                });
                            }
                        }
                    });
            });
    }

    fn show_summary(&self, ui: &mut egui::Ui) {
        let summary = ReportSummary::from_results(&self.results);
        let card_width = ((ui.available_width() - 40.0) / 6.0).max(72.0);
        ui.horizontal(|ui| {
            summary_card(ui, card_width, "FILES", summary.files_scanned, TEXT);
            summary_card(
                ui,
                card_width,
                "HIGH",
                summary.high,
                level_color(RiskLevel::High),
            );
            summary_card(
                ui,
                card_width,
                "MEDIUM",
                summary.medium,
                level_color(RiskLevel::Medium),
            );
            summary_card(
                ui,
                card_width,
                "LOW",
                summary.low,
                level_color(RiskLevel::Low),
            );
            summary_card(
                ui,
                card_width,
                "CLEAN",
                summary.clean,
                level_color(RiskLevel::Clean),
            );
            summary_card(
                ui,
                card_width,
                "ERRORS",
                summary.errors,
                level_color(RiskLevel::Error),
            );
        });
    }

    fn show_results(&mut self, root: &mut egui::Ui) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(10, 14, 19))
                    .inner_margin(egui::Margin::symmetric(20, 14)),
            )
            .show(root, |ui| {
                self.show_summary(ui);
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.add(
                        TextEdit::singleline(&mut self.query)
                            .desired_width(360.0)
                            .hint_text("Filter by file, path, level, or evidence"),
                    );
                    ui.checkbox(&mut self.only_flagged, "Flagged only");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new(&self.status).size(12.0).color(MUTED));
                    });
                });
                ui.add_space(8.0);

                let query = self.query.trim().to_ascii_lowercase();
                let visible: Vec<usize> = self
                    .results
                    .iter()
                    .enumerate()
                    .filter(|(_, result)| !self.only_flagged || result.highest_level.is_flagged())
                    .filter(|(_, result)| result_matches(result, &query))
                    .map(|(index, _)| index)
                    .collect();

                egui::Frame::NONE
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0, BORDER))
                    .corner_radius(10.0)
                    .inner_margin(egui::Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        draw_table_header(ui);
                        ui.separator();

                        if self.results.is_empty() && !self.scanning {
                            ui.vertical_centered(|ui| {
                                ui.add_space(54.0);
                                ui.label(
                                    RichText::new("No analysis results yet")
                                        .size(18.0)
                                        .color(TEXT),
                                );
                                ui.label(
                                    RichText::new(
                                        "Choose a target above or drag one into this window.",
                                    )
                                    .color(MUTED),
                                );
                                ui.add_space(54.0);
                            });
                        } else if visible.is_empty() {
                            ui.vertical_centered(|ui| {
                                ui.add_space(44.0);
                                ui.label(
                                    RichText::new("No results match the current filter.")
                                        .color(MUTED),
                                );
                                ui.add_space(44.0);
                            });
                        } else {
                            ScrollArea::vertical()
                                .auto_shrink([false, false])
                                .max_height(ui.available_height())
                                .show_rows(ui, 34.0, visible.len(), |ui, row_range| {
                                    for row in row_range {
                                        let index = visible[row];
                                        let result = &self.results[index];
                                        let selected = self.selected == Some(index);
                                        let response = draw_result_row(ui, result, selected);
                                        if response.clicked() {
                                            self.selected = Some(index);
                                        }
                                        response.on_hover_text(result.path.to_string_lossy());
                                    }
                                });
                        }
                    });
            });
    }

    fn show_details(&mut self, root: &mut egui::Ui) {
        if self.selected.is_none() {
            return;
        }
        egui::Panel::bottom("details")
            .resizable(true)
            .default_size(250.0)
            .min_size(170.0)
            .frame(egui::Frame::NONE.fill(PANEL_ALT).inner_margin(egui::Margin::symmetric(20, 13)))
            .show(root, |ui| {
                let Some(result) = self
                    .selected
                    .and_then(|index| self.results.get(index))
                    .cloned()
                else {
                    self.selected = None;
                    return;
                };
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(result.highest_level.label())
                            .strong()
                            .color(level_color(result.highest_level)),
                    );
                    ui.label(RichText::new(&result.file_name).size(17.0).strong().color(TEXT));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Close").clicked() {
                            self.selected = None;
                        }
                        if ui.small_button("Open location").clicked() {
                            reveal_in_explorer(&result.path);
                        }
                        if ui.small_button("Copy SHA-256").clicked() {
                            ui.ctx().copy_text(result.sha256.clone());
                        }
                    });
                });
                ui.label(RichText::new(result.path.to_string_lossy()).size(12.0).color(MUTED));
                ui.add_space(7.0);

                ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("detail_metadata")
                        .num_columns(4)
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            metadata_pair(ui, "Type", &result.file_kind);
                            metadata_pair(ui, "Architecture", &result.architecture);
                            ui.end_row();
                            metadata_pair(ui, "Size", &format_bytes(result.size_bytes));
                            metadata_pair(
                                ui,
                                "Signature blob",
                                if result.embedded_signature {
                                    "Present; trust not validated"
                                } else {
                                    "Not found"
                                },
                            );
                            ui.end_row();
                        });
                    if !result.sha256.is_empty() {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("SHA-256").size(11.0).color(MUTED));
                            ui.label(RichText::new(&result.sha256).monospace().size(11.0));
                        });
                    }
                    ui.add_space(8.0);

                    if let Some(error) = &result.error {
                        evidence_box(ui, RiskLevel::Error, 0, "Analysis error", error);
                    } else if result.findings.is_empty() {
                        evidence_box(
                            ui,
                            RiskLevel::Clean,
                            100,
                            "No selected capability evidence found",
                            "No matching import, dynamic-resolution pattern, API string, or selected marker was identified. This is not a guarantee that packed or runtime-generated behavior is absent.",
                        );
                    } else {
                        for finding in &result.findings {
                            evidence_box(
                                ui,
                                finding.level,
                                finding.confidence,
                                &finding.title,
                                &finding.detail,
                            );
                        }
                    }
                    if !result.relevant_imports.is_empty() {
                        ui.add_space(7.0);
                        ui.label(RichText::new("RELEVANT IMPORTS").size(11.0).strong().color(GOLD));
                        ui.label(RichText::new(result.relevant_imports.join("  |  ")).monospace().size(11.0));
                    }
                });
            });
    }

    fn show_methodology(&mut self, ctx: &egui::Context) {
        if !self.show_methodology {
            return;
        }
        egui::Window::new("OroResea methodology")
            .open(&mut self.show_methodology)
            .resizable(true)
            .default_width(610.0)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("Static capability mode")
                        .size(17.0)
                        .strong()
                        .color(TEXT),
                );
                ui.add_space(6.0);
                methodology_row(ui, RiskLevel::High, "Direct PE import of SetWindowDisplayAffinity. This confirms capability, not the affinity value used at runtime.");
                methodology_row(ui, RiskLevel::Medium, "Embedded API name combined with GetProcAddress or LdrGetProcedureAddress evidence.");
                methodology_row(ui, RiskLevel::Low, "API-name or WDA marker text without a confirmed call mechanism.");
                methodology_row(ui, RiskLevel::Informational, "GetWindowDisplayAffinity can inspect protection but does not apply it.");
                methodology_row(ui, RiskLevel::Informational, "Set/GetProcessMitigationPolicy imports show mitigation capability or inspection only. Effective CIG requires live Windows policy readback.");
                methodology_row(ui, RiskLevel::Informational, "DLL search and LoadLibrary imports are capability evidence. They do not prove a hardening call succeeded or that a load was hostile.");
                ui.separator();
                ui.label(
                    RichText::new("Protection posture mode")
                        .size(17.0)
                        .strong()
                        .color(TEXT),
                );
                ui.add_space(6.0);
                posture_methodology_row(
                    ui,
                    PostureVerdict::Pass,
                    "The named control was observed in the expected state. A pass reduces attack surface; it is not a claim that injection is impossible.",
                );
                posture_methodology_row(
                    ui,
                    PostureVerdict::Fail,
                    "A directly queried foundational mitigation is disabled, or embedded-signature trust validation was rejected.",
                );
                posture_methodology_row(
                    ui,
                    PostureVerdict::Warning,
                    "The posture is weaker, mixed, or requires interpretation. Attached debuggers and executable memory are observations here because development tools and JIT runtimes can be legitimate.",
                );
                posture_methodology_row(
                    ui,
                    PostureVerdict::Unknown,
                    "The available evidence cannot determine the control's state.",
                );
                posture_methodology_row(
                    ui,
                    PostureVerdict::Unavailable,
                    "The check needs a live process, elevated access, continuous telemetry, or system policy data. It is never silently treated as disabled.",
                );
                ui.label(
                    "Static checks read PE mitigation metadata and run cache-only Authenticode trust verification. Catalog-only signatures are not resolved by the embedded-certificate inspection, and offline revocation context can limit trust conclusions.",
                );
                ui.add_space(5.0);
                ui.label(
                    "Live snapshots query Windows process mitigations, PPL, debugger state, module paths, executable-memory metadata, top-level windows, and WDA. WDAC decisions and historical process-handle access require policy/event telemetry and remain unavailable here.",
                );
                ui.separator();
                ui.label(
                    RichText::new("Safety and interpretation")
                        .size(17.0)
                        .strong()
                        .color(TEXT),
                );
                ui.label("OroResea never launches a selected file, injects into a process, changes mitigations, reads target memory contents, patches, or modifies a target. Packed code, runtime-generated calls, later module loads, administrator-level attacks, and kernel activity can fall outside a static or point-in-time snapshot.");
            });
    }
}

impl eframe::App for OroReseaApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();
        self.poll_posture();
        if self.scanning || self.posture_busy {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_dropped_files(&ctx);
        self.show_header(ui);
        self.show_mode_tabs(ui);
        match self.mode {
            AppMode::WdaEvidence => {
                self.show_target_panel(ui);
                self.show_details(ui);
                self.show_results(ui);
            }
            AppMode::ProtectionPosture => {
                self.show_posture_target_panel(ui);
                self.show_posture_workspace(ui);
            }
        }
        self.show_methodology(&ctx);
    }
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(TEXT);
    visuals.panel_fill = PANEL;
    visuals.window_fill = PANEL_ALT;
    visuals.extreme_bg_color = Color32::from_rgb(8, 12, 17);
    visuals.faint_bg_color = Color32::from_rgb(22, 29, 38);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(16, 22, 30);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(28, 37, 47);
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(28, 37, 47);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(43, 53, 64);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, GOLD);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.bg_fill = Color32::from_rgb(50, 60, 72);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, GOLD);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.open.bg_fill = Color32::from_rgb(42, 51, 62);
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, GOLD);
    visuals.widgets.open.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.selection.bg_fill = Color32::from_rgb(78, 62, 31);
    visuals.selection.stroke = Stroke::new(1.0, GOLD);
    visuals.disabled_alpha = 0.58;
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    ctx.set_style_of(egui::Theme::Dark, style);
}

fn summary_card(ui: &mut egui::Ui, width: f32, label: &str, value: usize, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 65.0), Sense::hover());
    ui.painter().rect(
        rect,
        9.0,
        PANEL_ALT,
        Stroke::new(1.0, BORDER),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        rect.left_top() + Vec2::new(13.0, 12.0),
        egui::Align2::LEFT_TOP,
        value.to_string(),
        FontId::proportional(21.0),
        color,
    );
    ui.painter().text(
        rect.left_bottom() + Vec2::new(13.0, -11.0),
        egui::Align2::LEFT_BOTTOM,
        label,
        FontId::proportional(10.0),
        MUTED,
    );
}

fn show_posture_summary(ui: &mut egui::Ui, assessment: &PostureAssessment) {
    let summary = assessment.summary();
    let card_width = ((ui.available_width() - 48.0) / 7.0).max(64.0);
    ui.horizontal(|ui| {
        summary_card(
            ui,
            card_width,
            "PASS",
            summary.pass,
            posture_color(PostureVerdict::Pass),
        );
        summary_card(
            ui,
            card_width,
            "FAIL",
            summary.fail,
            posture_color(PostureVerdict::Fail),
        );
        summary_card(
            ui,
            card_width,
            "WARNING",
            summary.warning,
            posture_color(PostureVerdict::Warning),
        );
        summary_card(
            ui,
            card_width,
            "INFO",
            summary.informational,
            posture_color(PostureVerdict::Informational),
        );
        summary_card(
            ui,
            card_width,
            "UNKNOWN",
            summary.unknown,
            posture_color(PostureVerdict::Unknown),
        );
        summary_card(
            ui,
            card_width,
            "UNAVAILABLE",
            summary.unavailable,
            posture_color(PostureVerdict::Unavailable),
        );
        summary_card(
            ui,
            card_width,
            "ERRORS",
            summary.errors,
            posture_color(PostureVerdict::Error),
        );
    });
}

fn draw_process_row(ui: &mut egui::Ui, process: &ProcessSummary, selected: bool) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 58.0), Sense::click());
    if selected || response.hovered() {
        ui.painter().rect(
            rect,
            7.0,
            if selected {
                Color32::from_rgb(40, 48, 58)
            } else {
                Color32::from_rgb(24, 32, 41)
            },
            Stroke::new(1.0, if selected { GOLD } else { BORDER }),
            egui::StrokeKind::Inside,
        );
    }

    let painter = ui
        .painter()
        .with_clip_rect(rect.shrink2(Vec2::new(8.0, 2.0)));
    painter.text(
        rect.left_top() + Vec2::new(9.0, 7.0),
        egui::Align2::LEFT_TOP,
        &process.executable_name,
        FontId::proportional(13.0),
        TEXT,
    );
    painter.text(
        rect.right_top() + Vec2::new(-9.0, 8.0),
        egui::Align2::RIGHT_TOP,
        format!("PID {}", process.pid),
        FontId::monospace(10.0),
        GOLD,
    );
    let window_text = process
        .windows
        .value
        .as_ref()
        .map(|windows| {
            format!(
                "{} windows / {} visible",
                windows.top_level, windows.visible
            )
        })
        .unwrap_or_else(|| "window metadata unavailable".to_owned());
    painter.text(
        rect.left_top() + Vec2::new(9.0, 26.0),
        egui::Align2::LEFT_TOP,
        format!(
            "PPID {}  •  {} threads  •  {window_text}",
            process.parent_pid, process.thread_count
        ),
        FontId::proportional(10.0),
        MUTED,
    );
    let path = process
        .executable_path
        .value
        .as_deref()
        .unwrap_or("Executable path unavailable");
    painter.text(
        rect.left_bottom() + Vec2::new(9.0, -6.0),
        egui::Align2::LEFT_BOTTOM,
        path,
        FontId::monospace(9.5),
        Color32::from_rgb(167, 179, 191),
    );

    response.on_hover_text(
        process
            .executable_path
            .value
            .as_deref()
            .or(process.executable_path.message.as_deref())
            .unwrap_or("No executable path was returned."),
    )
}

fn posture_check_box(ui: &mut egui::Ui, check: &PostureCheck) {
    let color = posture_color(check.verdict);
    egui::Frame::NONE
        .fill(Color32::from_rgb(12, 18, 24))
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(7.0)
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(check.verdict.label())
                        .size(10.0)
                        .strong()
                        .color(color),
                );
                ui.label(RichText::new(&check.title).strong().color(TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(check.kind.label())
                            .size(10.0)
                            .strong()
                            .color(MUTED),
                    );
                });
            });
            ui.label(RichText::new(&check.detail).size(11.0).color(MUTED));
            if let Some(evidence) = &check.evidence {
                ui.add_space(3.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Evidence").size(10.0).strong().color(GOLD));
                    ui.label(
                        RichText::new(evidence)
                            .monospace()
                            .size(10.0)
                            .color(Color32::from_rgb(184, 197, 210)),
                    );
                });
            }
            if let Some(error) = &check.error {
                ui.add_space(3.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("Collection note")
                            .size(10.0)
                            .strong()
                            .color(posture_color(PostureVerdict::Error)),
                    );
                    ui.label(RichText::new(error).size(10.0).color(MUTED));
                });
            }
        });
    ui.add_space(5.0);
}

fn process_matches(process: &ProcessSummary, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    process.executable_name.to_ascii_lowercase().contains(query)
        || process.pid.to_string().contains(query)
        || process
            .executable_path
            .value
            .as_deref()
            .is_some_and(|path| path.to_ascii_lowercase().contains(query))
}

fn posture_target_label(assessment: &PostureAssessment) -> String {
    assessment
        .target
        .process_name
        .clone()
        .or_else(|| {
            assessment
                .target
                .path
                .as_ref()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "Unknown target".to_owned())
}

fn posture_target_subtitle(assessment: &PostureAssessment) -> String {
    let mut parts = Vec::new();
    if let Some(pid) = assessment.target.pid {
        parts.push(format!("PID {pid}"));
    } else {
        parts.push("pre-launch file analysis".to_owned());
    }
    if let Some(path) = &assessment.target.path {
        parts.push(path.to_string_lossy().into_owned());
    } else {
        parts.push("executable path unavailable".to_owned());
    }
    parts.push(format!("captured {}", assessment.captured_unix_seconds));
    parts.join("  •  ")
}

fn draw_table_header(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 22.0), Sense::hover());
    let columns = table_columns(rect);
    for (cell, label) in
        columns
            .iter()
            .zip(["LEVEL", "FILE", "TYPE", "ARCH", "SIZE", "TOP EVIDENCE"])
    {
        paint_cell(ui, *cell, label, MUTED, 10.0);
    }
}

fn draw_result_row(ui: &mut egui::Ui, result: &ScanResult, selected: bool) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), Sense::click());
    if selected || response.hovered() {
        ui.painter().rect_filled(
            rect,
            6.0,
            if selected {
                Color32::from_rgb(35, 44, 55)
            } else {
                Color32::from_rgb(24, 32, 41)
            },
        );
    }
    let columns = table_columns(rect);
    let evidence = result
        .findings
        .first()
        .map(|finding| finding.title.as_str())
        .or(result.error.as_deref())
        .unwrap_or("No selected capability evidence found");
    let values = [
        result.highest_level.label().to_owned(),
        result.file_name.clone(),
        result.file_kind.clone(),
        result.architecture.clone(),
        format_bytes(result.size_bytes),
        evidence.to_owned(),
    ];
    let colors = [
        level_color(result.highest_level),
        TEXT,
        MUTED,
        TEXT,
        TEXT,
        MUTED,
    ];
    for ((cell, value), color) in columns.iter().zip(values).zip(colors) {
        paint_cell(ui, *cell, &value, color, 12.0);
    }
    response
}

fn table_columns(rect: egui::Rect) -> [egui::Rect; 6] {
    let fixed = [82.0, 260.0, 185.0, 75.0, 90.0];
    let mut x = rect.left();
    let mut columns = [rect; 6];
    for (index, width) in fixed.into_iter().enumerate() {
        columns[index] = egui::Rect::from_min_max(
            egui::pos2(x, rect.top()),
            egui::pos2((x + width).min(rect.right()), rect.bottom()),
        );
        x += width;
    }
    columns[5] = egui::Rect::from_min_max(
        egui::pos2(x.min(rect.right()), rect.top()),
        rect.right_bottom(),
    );
    columns
}

fn paint_cell(ui: &egui::Ui, rect: egui::Rect, text: &str, color: Color32, font_size: f32) {
    if rect.width() <= 0.0 {
        return;
    }
    ui.painter()
        .with_clip_rect(rect.shrink2(Vec2::new(4.0, 0.0)))
        .text(
            egui::pos2(rect.left() + 5.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            text,
            FontId::proportional(font_size),
            color,
        );
}

fn metadata_pair(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).size(11.0).color(MUTED));
    ui.label(RichText::new(value).size(12.0).color(TEXT));
}

fn evidence_box(ui: &mut egui::Ui, level: RiskLevel, confidence: u8, title: &str, detail: &str) {
    egui::Frame::NONE
        .fill(Color32::from_rgb(12, 18, 24))
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(7.0)
        .inner_margin(egui::Margin::symmetric(11, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(level.label())
                        .size(10.0)
                        .strong()
                        .color(level_color(level)),
                );
                ui.label(RichText::new(title).strong().color(TEXT));
                if confidence > 0 {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{confidence}% confidence"))
                                .size(11.0)
                                .color(MUTED),
                        );
                    });
                }
            });
            ui.label(RichText::new(detail).size(12.0).color(MUTED));
        });
    ui.add_space(5.0);
}

fn methodology_row(ui: &mut egui::Ui, level: RiskLevel, detail: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.add_sized(
            [78.0, 20.0],
            egui::Label::new(
                RichText::new(level.label())
                    .strong()
                    .color(level_color(level)),
            ),
        );
        ui.label(detail);
    });
}

fn posture_methodology_row(ui: &mut egui::Ui, verdict: PostureVerdict, detail: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.add_sized(
            [94.0, 20.0],
            egui::Label::new(
                RichText::new(verdict.label())
                    .strong()
                    .color(posture_color(verdict)),
            ),
        );
        ui.label(detail);
    });
}

fn result_matches(result: &ScanResult, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    result.file_name.to_ascii_lowercase().contains(query)
        || result
            .path
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains(query)
        || result
            .highest_level
            .label()
            .to_ascii_lowercase()
            .contains(query)
        || result.findings.iter().any(|finding| {
            finding.title.to_ascii_lowercase().contains(query)
                || finding.detail.to_ascii_lowercase().contains(query)
        })
}

fn level_color(level: RiskLevel) -> Color32 {
    match level {
        RiskLevel::High => Color32::from_rgb(255, 112, 123),
        RiskLevel::Medium => Color32::from_rgb(255, 183, 91),
        RiskLevel::Low => Color32::from_rgb(231, 210, 105),
        RiskLevel::Informational => Color32::from_rgb(100, 196, 229),
        RiskLevel::Clean => Color32::from_rgb(101, 215, 165),
        RiskLevel::Error => Color32::from_rgb(255, 125, 135),
    }
}

fn posture_color(verdict: PostureVerdict) -> Color32 {
    match verdict {
        PostureVerdict::Pass => Color32::from_rgb(101, 215, 165),
        PostureVerdict::Fail => Color32::from_rgb(255, 112, 123),
        PostureVerdict::Warning => Color32::from_rgb(255, 183, 91),
        PostureVerdict::Informational => Color32::from_rgb(100, 196, 229),
        PostureVerdict::Unknown => Color32::from_rgb(190, 166, 235),
        PostureVerdict::Unavailable => Color32::from_rgb(153, 166, 179),
        PostureVerdict::Error => Color32::from_rgb(255, 125, 170),
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let value = bytes as f64;
    if value >= GIB {
        format!("{:.2} GiB", value / GIB)
    } else if value >= MIB {
        format!("{:.2} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.1} KiB", value / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn truncate_middle(value: &str, max_chars: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= max_chars || max_chars < 5 {
        return value.to_owned();
    }
    let left = (max_chars - 1) / 2;
    let right = max_chars - left - 1;
    format!(
        "{}…{}",
        chars[..left].iter().collect::<String>(),
        chars[chars.len() - right..].iter().collect::<String>()
    )
}

fn reveal_in_explorer(path: &Path) {
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("explorer.exe")
            .arg(format!("/select,{}", path.display()))
            .spawn();
    }
}
