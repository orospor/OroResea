#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod model;
mod report;
mod scanner;

use app::OroReseaApp;
use eframe::egui;
use std::sync::Arc;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("OroResea")
            .with_inner_size([1220.0, 790.0])
            .with_min_inner_size([920.0, 620.0])
            .with_icon(Arc::new(app_icon())),
        ..Default::default()
    };

    eframe::run_native(
        "OroResea",
        options,
        Box::new(|cc| Ok(Box::new(OroReseaApp::new(cc)))),
    )
}

fn app_icon() -> egui::IconData {
    let size = 64usize;
    let mut rgba = vec![0u8; size * size * 4];
    let center = (size as f32 - 1.0) / 2.0;
    for y in 0..size {
        for x in 0..size {
            let index = (y * size + x) * 4;
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let distance = (dx * dx + dy * dy).sqrt();
            let inside_card = (5..59).contains(&x) && (5..59).contains(&y);
            let ring = (16.0..=25.0).contains(&distance);
            let (red, green, blue, alpha) = if ring {
                (222, 180, 83, 255)
            } else if inside_card {
                (15, 22, 30, 255)
            } else {
                (0, 0, 0, 0)
            };
            rgba[index] = red;
            rgba[index + 1] = green;
            rgba[index + 2] = blue;
            rgba[index + 3] = alpha;
        }
    }
    egui::IconData {
        rgba,
        width: size as u32,
        height: size as u32,
    }
}
