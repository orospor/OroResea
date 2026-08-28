use crate::{
    model::{ReportSummary, RiskLevel, ScanResult},
    report,
    scanner::{self, ScanMessage},
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

pub struct OroReseaApp {
    source_text: String,
    results: Vec<ScanResult>,
    selected: Option<usize>,
    query: String,
    only_flagged: bool,
    scan_rx: Option<Receiver<ScanMessage>>,
    cancel: Option<Arc<AtomicBool>>,
    scanning: bool,
    progress_current: usize,
    progress_total: usize,
    current_file: String,
    last_elapsed: Option<Duration>,
    status: String,
    show_methodology: bool,
}

impl OroReseaApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);
        Self {
            source_text: String::new(),
            results: Vec::new(),
            selected: None,
            query: String::new(),
            only_flagged: false,
            scan_rx: None,
            cancel: None,
            scanning: false,
            progress_current: 0,
            progress_total: 0,
            current_file: String::new(),
            last_elapsed: None,
            status: "Choose a Windows binary or a directory to begin.".to_owned(),
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

        let (rx, cancel) = scanner::spawn_scan(source);
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

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|input| input.raw.dropped_files.clone());
        if let Some(path) = dropped.first().map(|file| file.path().to_owned()) {
            self.source_text = path.to_string_lossy().into_owned();
            self.status = "Dropped target selected. Press Scan to analyze it.".to_owned();
        }
    }

    fn export_json(&mut self) {
        if self.results.is_empty() {
            self.status = "There are no results to export.".to_owned();
            return;
        }
        if let Some(path) = FileDialog::new()
            .set_file_name("OroResea-report.json")
            .add_filter("JSON report", &["json"])
            .save_file()
        {
            self.status = match report::write_json(&path, &self.source_text, &self.results) {
                Ok(()) => format!("JSON report saved to {}", path.display()),
                Err(error) => format!("Could not export JSON: {error}"),
            };
        }
    }

    fn export_csv(&mut self) {
        if self.results.is_empty() {
            self.status = "There are no results to export.".to_owned();
            return;
        }
        if let Some(path) = FileDialog::new()
            .set_file_name("OroResea-report.csv")
            .add_filter("CSV report", &["csv"])
            .save_file()
        {
            self.status = match report::write_csv(&path, &self.results) {
                Ok(()) => format!("CSV report saved to {}", path.display()),
                Err(error) => format!("Could not export CSV: {error}"),
            };
        }
    }

    fn export_html(&mut self) {
        if self.results.is_empty() {
            self.status = "There are no results to export.".to_owned();
            return;
        }
        if let Some(path) = FileDialog::new()
            .set_file_name("OroResea-report.html")
            .add_filter("HTML report", &["html"])
            .save_file()
        {
            self.status = match report::write_html(&path, &self.source_text, &self.results) {
                Ok(()) => format!("HTML report saved to {}", path.display()),
                Err(error) => format!("Could not export HTML: {error}"),
            };
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
                            RichText::new("Windows display-affinity evidence analyzer")
                                .size(12.0)
                                .color(MUTED),
                        );
                    });
                    ui.add_space((ui.available_width() - 205.0).max(8.0));
                    if ui.button("Methodology").clicked() {
                        self.show_methodology = true;
                    }
                    ui.menu_button("Export", |ui| {
                        ui.add_enabled_ui(!self.results.is_empty(), |ui| {
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
                            "No WDA evidence found",
                            "No direct import, dynamic-resolution pattern, API string, or named WDA marker was identified. This is not a guarantee that packed or runtime-generated behavior is absent.",
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
                ui.label(RichText::new("Evidence levels").size(17.0).strong().color(TEXT));
                ui.add_space(6.0);
                methodology_row(ui, RiskLevel::High, "Direct PE import of SetWindowDisplayAffinity. This confirms capability, not the affinity value used at runtime.");
                methodology_row(ui, RiskLevel::Medium, "Embedded API name combined with GetProcAddress or LdrGetProcedureAddress evidence.");
                methodology_row(ui, RiskLevel::Low, "API-name or WDA marker text without a confirmed call mechanism.");
                methodology_row(ui, RiskLevel::Informational, "GetWindowDisplayAffinity can inspect protection but does not apply it.");
                ui.separator();
                ui.label(RichText::new("Safety and interpretation").size(17.0).strong().color(TEXT));
                ui.label("Files are read as data and hashed locally. OroResea never launches, loads, injects into, patches, or modifies a target. Packed code, encrypted strings, runtime downloads, and generated calls can evade static analysis. A clean result is therefore not a guarantee of runtime behavior.");
            });
    }
}

impl eframe::App for OroReseaApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();
        if self.scanning {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_dropped_files(&ctx);
        self.show_header(ui);
        self.show_target_panel(ui);
        self.show_details(ui);
        self.show_results(ui);
        self.show_methodology(&ctx);
    }
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = PANEL;
    visuals.window_fill = PANEL_ALT;
    visuals.extreme_bg_color = Color32::from_rgb(8, 12, 17);
    visuals.faint_bg_color = Color32::from_rgb(22, 29, 38);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(28, 37, 47);
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(28, 37, 47);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(43, 53, 64);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, GOLD);
    visuals.selection.bg_fill = Color32::from_rgb(78, 62, 31);
    visuals.selection.stroke = Stroke::new(1.0, GOLD);
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
        .unwrap_or("No WDA evidence found");
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
