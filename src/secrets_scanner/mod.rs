#[allow(unused_imports, unused_variables, dead_code, clippy::needless_return)]
use anyhow::{Context, Result};
use colored::*;
use regex::Regex;
use serde::Serialize;
use std::fs;
use std::path::Path;
use tabled::{Table, Tabled};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
struct SecretPattern {
    name: &'static str,
    pattern: &'static str,
    severity: &'static str,
}

const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern { name: "AWS Access Key", pattern: r"(?i)AKIA[0-9A-Z]{16}", severity: "CRITICAL" },
    SecretPattern { name: "AWS Secret Key", pattern: r"(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*[A-Za-z0-9/+=]{40}", severity: "CRITICAL" },
    SecretPattern { name: "GitHub Token", pattern: r"gh[pousr]_[A-Za-z0-9_]{36,255}", severity: "CRITICAL" },
    SecretPattern { name: "GitHub Classic Token", pattern: r"ghp_[A-Za-z0-9]{36}", severity: "CRITICAL" },
    SecretPattern { name: "Slack Token", pattern: r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}", severity: "HIGH" },
    SecretPattern { name: "Slack Webhook", pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}", severity: "HIGH" },
    SecretPattern { name: "Google API Key", pattern: r"AIza[0-9A-Za-z\-_]{35}", severity: "HIGH" },
    SecretPattern { name: "Generic API Key", pattern: r#"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9\-_]{20,}"#, severity: "HIGH" },
    SecretPattern { name: "Generic Secret", pattern: r#"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*["']?[^\s"']{8,}"#, severity: "HIGH" },
    SecretPattern { name: "Private Key", pattern: r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", severity: "CRITICAL" },
    SecretPattern { name: "Bearer Token", pattern: r#"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}"#, severity: "HIGH" },
    SecretPattern { name: "JWT Token", pattern: r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", severity: "MEDIUM" },
    SecretPattern { name: "Basic Auth", pattern: r"(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}", severity: "HIGH" },
    SecretPattern { name: "Azure Key", pattern: r"(?i)(?:azure|az)[_-]?(?:key|secret|password)\s*[=:]\s*[^\s]{10,}", severity: "HIGH" },
    SecretPattern { name: "Stripe Key", pattern: r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}", severity: "CRITICAL" },
    SecretPattern { name: "SendGrid Key", pattern: r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", severity: "HIGH" },
    SecretPattern { name: "Twilio Key", pattern: r"SK[a-f0-9]{32}", severity: "HIGH" },
    SecretPattern { name: "Database URL", pattern: r"(?i)(?:mysql|postgres|postgresql|mongodb|redis)://[^\s]{10,}", severity: "HIGH" },
    SecretPattern { name: "IP + Credentials", pattern: r"(?i)(?:ftp|ssh|rdp)://[^:]+:[^@]+@[\d.]+", severity: "CRITICAL" },
    SecretPattern { name: "Hardcoded Password", pattern: r#"(?i)(?:password|passwd|pwd)\s*=\s*["'][^"']{6,}["']"#, severity: "HIGH" },
];

/// Files/dirs to skip
const SKIP_DIRS: &[&str] = &[
    ".git", "node_modules", "target", "__pycache__", ".venv",
    "venv", "dist", "build", ".next", ".cargo",
];

const SKIP_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "woff2",
    "ttf", "eot", "mp3", "mp4", "avi", "zip", "gz", "tar",
    "jar", "war", "class", "pyc", "exe", "dll", "so", "o",
    "pdf", "doc", "docx", "xls", "xlsx",
];

#[derive(Debug, Serialize, Tabled, Clone)]
struct SecretFinding {
    #[tabled(rename = "File")]
    file: String,
    #[tabled(rename = "Line")]
    line_num: usize,
    #[tabled(rename = "Type")]
    secret_type: String,
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Match Preview")]
    preview: String,
}

#[derive(Debug, Serialize, Tabled)]
struct SeveritySummary {
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Count")]
    count: usize,
}

#[derive(Debug, Serialize)]
struct ScanReport {
    total_files_scanned: usize,
    total_findings: usize,
    findings: Vec<SecretFinding>,
    severity_summary: Vec<SeveritySummary>,
}

fn should_skip_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name)
}

fn should_skip_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        SKIP_EXTENSIONS.iter().any(|&e| e == ext.to_lowercase())
    } else {
        false
    }
}

/// Redact the match for display (show first 8 and last 4 chars)
fn redact_match(m: &str) -> String {
    let trimmed = m.trim();
    if trimmed.len() <= 16 {
        format!("{}...", &trimmed[..trimmed.len().min(8)])
    } else {
        format!("{}...{}", &trimmed[..8], &trimmed[trimmed.len()-4..])
    }
}

fn make_relative(path: &str, base: &str) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .trim_start_matches('/')
        .to_string()
}

pub fn run(input: &str, output: Option<&str>, max_file_size_kb: u64) -> Result<()> {
    println!("{}", "🔐 Secrets Scanner".cyan().bold());
    println!("{}", "=".repeat(60).dimmed());

    let path = Path::new(input);
    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", input);
    }

    // Compile regex patterns
    let compiled: Vec<(String, Regex, String)> = SECRET_PATTERNS
        .iter()
        .filter_map(|p| {
            Regex::new(p.pattern)
                .ok()
                .map(|r| (p.name.to_string(), r, p.severity.to_string()))
        })
        .collect();

    println!("  Loaded {} secret patterns", compiled.len().to_string().white().bold());
    println!("  Max file size: {} KB", max_file_size_kb);

    let mut findings: Vec<SecretFinding> = Vec::new();
    let mut files_scanned = 0usize;
    let max_bytes = max_file_size_kb * 1024;

    let entries: Vec<walkdir::DirEntry> = if path.is_dir() {
        WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    !should_skip_dir(e.file_name().to_str().unwrap_or(""))
                } else {
                    true
                }
            })
            .filter_map(|e| e.ok())
            .collect()
    } else {
        // Single file
        WalkDir::new(path)
            .max_depth(0)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .collect()
    };

    for entry in entries {
        let file_path = entry.path();

        if !file_path.is_file() || should_skip_file(file_path) {
            continue;
        }

        // Skip large files
        if let Ok(meta) = fs::metadata(file_path) {
            if meta.len() > max_bytes {
                continue;
            }
        }

        // Try to read as text
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue, // Skip binary files
        };

        files_scanned += 1;

        let display_path = make_relative(
            file_path.to_str().unwrap_or(""),
            input.trim_end_matches('/'),
        );

        for (line_num, line) in content.lines().enumerate() {
            for (name, regex, severity) in &compiled {
                if let Some(m) = regex.find(line) {
                    findings.push(SecretFinding {
                        file: display_path.clone(),
                        line_num: line_num + 1,
                        secret_type: name.clone(),
                        severity: match severity.as_str() {
                            "CRITICAL" => "🔴 CRITICAL".to_string(),
                            "HIGH" => "🟠 HIGH".to_string(),
                            _ => "🟡 MEDIUM".to_string(),
                        },
                        preview: redact_match(m.as_str()),
                    });
                }
            }
        }
    }

    println!("  Scanned {} files\n", files_scanned.to_string().white().bold());

    if findings.is_empty() {
        println!("  {} No secrets detected! Your code looks clean.", "✅".green());
    } else {
        // Sort by severity
        findings.sort_by(|a, b| {
            let sev_order = |s: &str| -> u8 {
                if s.contains("CRITICAL") { 0 }
                else if s.contains("HIGH") { 1 }
                else { 2 }
            };
            sev_order(&a.severity).cmp(&sev_order(&b.severity))
        });

        println!("  {} {} secrets found in {} files!\n",
            "🚨".red(),
            findings.len().to_string().red().bold(),
            files_scanned
        );

        let table = Table::new(&findings).to_string();
        println!("{}", table);

        // Severity summary
        println!("\n{}", "📊 Severity Summary".green().bold());
        let mut sev_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for f in &findings {
            *sev_counts.entry(f.severity.clone()).or_insert(0) += 1;
        }
        let summary: Vec<SeveritySummary> = sev_counts
            .into_iter()
            .map(|(severity, count)| SeveritySummary { severity, count })
            .collect();
        let summary_table = Table::new(&summary).to_string();
        println!("{}", summary_table);
    }

    // Export
    if let Some(out_path) = output {
        let mut sev_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for f in &findings {
            *sev_counts.entry(f.severity.clone()).or_insert(0) += 1;
        }

        let report = ScanReport {
            total_files_scanned: files_scanned,
            total_findings: findings.len(),
            findings,
            severity_summary: sev_counts
                .into_iter()
                .map(|(severity, count)| SeveritySummary { severity, count })
                .collect(),
        };
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(out_path, &json)
            .with_context(|| format!("Failed to write report: {}", out_path))?;
        println!("\n{} Report exported to {}", "📁".green(), out_path.white().bold());
    }

    println!("\n{}", "✅ Secret scan complete.".green().bold());
    Ok(())
}
