use serde::{Serialize, Deserialize};
use std::fs::{File, read_dir};
use std::io::{Write, Read};
use chrono::Utc;
use anyhow::Result;
use crate::network_tools::ScanResult;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub name: String,
    pub date: String,
    pub targets: Vec<String>,
    pub results: HashMap<String, ScanResult>,
}

pub struct ReportsManager;

impl ReportsManager {
    pub fn save_report(results: HashMap<String, ScanResult>) -> Result<String> {
        let report_id = Utc::now().format("%Y%m%d%H%M%S").to_string();
        let report = Report {
            id: report_id.clone(),
            name: format!("Scan Report {}", report_id),
            date: Utc::now().to_rfc3339(),
            targets: results.keys().cloned().collect(),
            results,
        };

        let filename = format!("report_{}.json", report_id);
        let mut file = File::create(&filename)?;
        let json = serde_json::to_string_pretty(&report)?;
        file.write_all(json.as_bytes())?;

        Ok(report_id)
    }

    pub fn get_report(report_id: &str) -> Result<Report> {
        let filename = format!("report_{}.json", report_id);
        let mut file = File::open(&filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let report: Report = serde_json::from_str(&contents)?;
        Ok(report)
    }

    pub fn get_all_reports() -> Result<Vec<Report>> {
        let mut reports = Vec::new();
        for entry in read_dir(".")? {
            let entry = entry?;
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();
            if filename_str.starts_with("report_") && filename_str.ends_with(".json") {
                let report_id = &filename_str[7..filename_str.len() - 5];
                if let Ok(report) = Self::get_report(report_id) {
                    reports.push(report);
                }
            }
        }
        Ok(reports)
    }
}