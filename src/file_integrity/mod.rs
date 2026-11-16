#[allow(unused_imports, unused_variables, dead_code, clippy::needless_return)]
use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tabled::{Table, Tabled};
use walkdir::WalkDir;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileRecord {
    path: String,
    sha256: String,
    size: u64,
    modified: String,
}

#[derive(Debug, Serialize, Tabled, Clone)]
struct IntegrityFinding {
    #[tabled(rename = "Status")]
    status: String,
    #[tabled(rename = "File")]
    file: String,
    #[tabled(rename = "Details")]
    details: String,
}

#[derive(Debug, Serialize)]
struct IntegrityReport {
    baseline_file: String,
    total_baseline: usize,
    total_current: usize,
    unchanged: usize,
    modified: usize,
    added: usize,
    removed: usize,
    findings: Vec<IntegrityFinding>,
}

fn hash_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn file_modified_time(path: &Path) -> String {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| {
            let duration = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
        .unwrap_or_else(|_| "unknown".to_string())
}

fn scan_directory(dir: &str) -> Result<Vec<FileRecord>> {
    let mut records = Vec::new();

    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let hash = match hash_file(path) {
            Ok(h) => h,
            Err(_) => continue, // Skip unreadable files
        };

        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let modified = file_modified_time(path);

        records.push(FileRecord {
            path: path.to_string_lossy().to_string(),
            sha256: hash,
            size,
            modified,
        });
    }

    Ok(records)
}

fn scan_file_list(list_path: &str) -> Result<Vec<FileRecord>> {
    let content = fs::read_to_string(list_path)
        .with_context(|| format!("Failed to read file list: {}", list_path))?;

    let mut records = Vec::new();

    for line in content.lines() {
        let file_path = line.trim();
        if file_path.is_empty() || file_path.starts_with('#') {
            continue;
        }

        let path = Path::new(file_path);
        if !path.exists() {
            continue;
        }

        if path.is_dir() {
            records.extend(scan_directory(file_path)?);
        } else {
            let hash = match hash_file(path) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let modified = file_modified_time(path);

            records.push(FileRecord {
                path: file_path.to_string(),
                sha256: hash,
                size,
                modified,
            });
        }
    }

    Ok(records)
}

pub fn run(input: &str, baseline: Option<&str>, output: Option<&str>, mode: &str) -> Result<()> {
    println!("{}", "🛡️ File Integrity Monitor".cyan().bold());
    println!("{}", "=".repeat(60).dimmed());

    match mode {
        "init" | "baseline" => {
            // Create baseline
            println!("{}", "📸 Creating baseline snapshot...".green().bold());

            let path = Path::new(input);
            let records = if path.is_dir() {
                scan_directory(input)?
            } else {
                scan_file_list(input)?
            };

            if records.is_empty() {
                println!("{}", "⚠ No files found to baseline.".yellow());
                return Ok(());
            }

            println!("  Hashed {} files", records.len().to_string().white().bold());

            let baseline_path = output.unwrap_or("fim-baseline.json");
            let json = serde_json::to_string_pretty(&records)?;
            fs::write(baseline_path, &json)
                .with_context(|| format!("Failed to write baseline: {}", baseline_path))?;

            println!("\n{} Baseline saved to {}", "📁".green(), baseline_path.white().bold());
            println!("  Run again with {} to check for changes.", "--mode check".cyan());
        }

        "check" | "verify" => {
            // Check against baseline
            let baseline_path = baseline.unwrap_or("fim-baseline.json");

            println!("{}", "🔍 Checking file integrity against baseline...".green().bold());
            println!("  Baseline: {}", baseline_path);

            let baseline_content = fs::read_to_string(baseline_path)
                .with_context(|| format!("Failed to read baseline: {}. Run with --mode init first.", baseline_path))?;

            let baseline_records: Vec<FileRecord> = serde_json::from_str(&baseline_content)
                .with_context(|| "Failed to parse baseline JSON")?;

            // Scan current state
            let path = Path::new(input);
            let current_records = if path.is_dir() {
                scan_directory(input)?
            } else {
                scan_file_list(input)?
            };

            println!("  Baseline files:  {}", baseline_records.len().to_string().white().bold());
            println!("  Current files:   {}", current_records.len().to_string().white().bold());

            // Build maps
            let baseline_map: HashMap<String, FileRecord> = baseline_records
                .iter()
                .map(|r| (r.path.clone(), r.clone()))
                .collect();

            let current_map: HashMap<String, FileRecord> = current_records
                .iter()
                .map(|r| (r.path.clone(), r.clone()))
                .collect();

            let mut findings: Vec<IntegrityFinding> = Vec::new();
            let mut unchanged = 0usize;
            let mut modified = 0usize;
            let mut added = 0usize;
            let mut removed = 0usize;

            // Check for modified and removed files
            for (path, base_rec) in &baseline_map {
                if let Some(curr_rec) = current_map.get(path) {
                    if base_rec.sha256 != curr_rec.sha256 {
                        modified += 1;
                        findings.push(IntegrityFinding {
                            status: "🔴 MODIFIED".to_string(),
                            file: path.clone(),
                            details: format!(
                                "Hash changed | Size: {}→{} | Modified: {}",
                                base_rec.size, curr_rec.size, curr_rec.modified
                            ),
                        });
                    } else if base_rec.size != curr_rec.size {
                        modified += 1;
                        findings.push(IntegrityFinding {
                            status: "🟠 SIZE CHANGED".to_string(),
                            file: path.clone(),
                            details: format!("Size: {}→{} bytes", base_rec.size, curr_rec.size),
                        });
                    } else {
                        unchanged += 1;
                    }
                } else {
                    removed += 1;
                    findings.push(IntegrityFinding {
                        status: "🟡 REMOVED".to_string(),
                        file: path.clone(),
                        details: "File no longer exists".to_string(),
                    });
                }
            }

            // Check for new files
            for path in current_map.keys() {
                if !baseline_map.contains_key(path) {
                    added += 1;
                    findings.push(IntegrityFinding {
                        status: "🔵 NEW".to_string(),
                        file: path.clone(),
                        details: "File not in baseline".to_string(),
                    });
                }
            }

            // Display results
            println!("\n{}", "📊 Integrity Check Results".green().bold());
            println!("  ✅ Unchanged:  {}", unchanged.to_string().green().bold());
            println!("  🔴 Modified:   {}", modified.to_string().red().bold());
            println!("  🔵 New files:  {}", added.to_string().blue().bold());
            println!("  🟡 Removed:    {}", removed.to_string().yellow().bold());

            if !findings.is_empty() {
                println!("\n{}", "🔍 Changes Detected".yellow().bold());

                // Sort: modified first
                findings.sort_by(|a, b| {
                    let order = |s: &str| -> u8 {
                        if s.contains("MODIFIED") { 0 }
                        else if s.contains("SIZE") { 1 }
                        else if s.contains("REMOVED") { 2 }
                        else { 3 }
                    };
                    order(&a.status).cmp(&order(&b.status))
                });

                let table = Table::new(&findings).to_string();
                println!("{}", table);
            } else {
                println!("\n  {} All files match baseline. No tampering detected.", "✅".green());
            }

            // Export
            if let Some(out_path) = output {
                let report = IntegrityReport {
                    baseline_file: baseline_path.to_string(),
                    total_baseline: baseline_records.len(),
                    total_current: current_records.len(),
                    unchanged,
                    modified,
                    added,
                    removed,
                    findings,
                };
                let json = serde_json::to_string_pretty(&report)?;
                fs::write(out_path, &json)
                    .with_context(|| format!("Failed to write report: {}", out_path))?;
                println!("\n{} Report exported to {}", "📁".green(), out_path.white().bold());
            }
        }

        _ => {
            println!("{}", "⚠ Invalid mode. Use --mode init (create baseline) or --mode check (verify integrity)".yellow());
        }
    }

    println!("\n{}", "✅ File integrity check complete.".green().bold());
    Ok(())
}
