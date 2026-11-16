#[allow(unused_imports, unused_variables, dead_code, clippy::needless_return)]
use anyhow::{Context, Result};
use colored::*;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use tabled::{Table, Tabled};

#[derive(Debug, Serialize, Tabled, Clone)]
struct DiffFinding {
    #[tabled(rename = "Change")]
    change_type: String,
    #[tabled(rename = "Rule/Line")]
    identifier: String,
    #[tabled(rename = "Before")]
    before: String,
    #[tabled(rename = "After")]
    after: String,
    #[tabled(rename = "Security Impact")]
    impact: String,
}

#[derive(Debug, Serialize, Tabled)]
struct DiffSummary {
    #[tabled(rename = "Metric")]
    metric: String,
    #[tabled(rename = "Value")]
    value: String,
}

#[derive(Debug, Serialize)]
struct DiffReport {
    file_before: String,
    file_after: String,
    total_rules_before: usize,
    total_rules_after: usize,
    added: usize,
    removed: usize,
    modified: usize,
    security_regressions: usize,
    findings: Vec<DiffFinding>,
}

/// Security-sensitive keywords — changes to these are flagged
const SECURITY_KEYWORDS: &[&str] = &[
    "any", "permit", "allow", "deny", "reject", "drop",
    "log", "logging", "disabled", "enabled",
    "0.0.0.0", "trust", "untrust", "dmz",
];

const RISKY_PORTS: &[&str] = &[
    "21", "22", "23", "25", "53", "135", "139", "445",
    "1433", "1434", "3306", "3389", "5432", "5900", "6379",
];

fn normalize_line(line: &str) -> String {
    line.trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

fn extract_rule_key(line: &str) -> String {
    // Try to extract a rule identifier (name, number, or first few tokens)
    let parts: Vec<&str> = line.split(|c: char| c == ',' || c == '\t' || c == '|')
        .map(|s| s.trim())
        .collect();
    if !parts.is_empty() {
        parts[0].to_string()
    } else {
        line.chars().take(40).collect()
    }
}

fn assess_security_impact(before: &str, after: &str, change: &str) -> String {
    let before_lower = before.to_lowercase();
    let after_lower = after.to_lowercase();

    // Deny -> Allow is always critical
    if (before_lower.contains("deny") || before_lower.contains("drop") || before_lower.contains("reject"))
        && (after_lower.contains("allow") || after_lower.contains("permit"))
    {
        return "🔴 CRITICAL: deny→allow".to_string();
    }

    // Allow -> Deny is an improvement
    if (before_lower.contains("allow") || before_lower.contains("permit"))
        && (after_lower.contains("deny") || after_lower.contains("drop"))
    {
        return "🟢 IMPROVED: allow→deny".to_string();
    }

    // Logging disabled
    if before_lower.contains("log") && !after_lower.contains("log") {
        return "🟠 HIGH: logging removed".to_string();
    }

    // Source changed to ANY
    if !before_lower.contains("any") && after_lower.contains("any") {
        return "🔴 CRITICAL: source/dest opened to ANY".to_string();
    }

    // ANY removed (improvement)
    if before_lower.contains("any") && !after_lower.contains("any") {
        return "🟢 IMPROVED: ANY restriction added".to_string();
    }

    // Risky ports added
    for port in RISKY_PORTS {
        if !before_lower.contains(port) && after_lower.contains(port) {
            return format!("🟠 HIGH: risky port {} opened", port);
        }
    }

    // New rule added with allow
    if change == "ADDED" && (after_lower.contains("allow") || after_lower.contains("permit")) {
        if after_lower.contains("any") {
            return "🔴 CRITICAL: new allow-any rule".to_string();
        }
        return "🟡 MEDIUM: new allow rule".to_string();
    }

    // Rule removed
    if change == "REMOVED" {
        if before_lower.contains("deny") || before_lower.contains("drop") {
            return "🟠 HIGH: deny rule removed".to_string();
        }
        return "🟡 MEDIUM: rule removed".to_string();
    }

    "🟡 LOW: modified".to_string()
}

pub fn run(before: &str, after: &str, output: Option<&str>, _context_lines: usize) -> Result<()> {
    println!("{}", "🔄 Security Config Diff".cyan().bold());
    println!("{}", "=".repeat(60).dimmed());

    let before_content = fs::read_to_string(before)
        .with_context(|| format!("Failed to read 'before' file: {}", before))?;
    let after_content = fs::read_to_string(after)
        .with_context(|| format!("Failed to read 'after' file: {}", after))?;

    let before_lines: Vec<String> = before_content
        .lines()
        .map(|l| l.to_string())
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#') && !l.trim().starts_with('!'))
        .collect();

    let after_lines: Vec<String> = after_content
        .lines()
        .map(|l| l.to_string())
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#') && !l.trim().starts_with('!'))
        .collect();

    println!("  Before: {} ({} rules/lines)", before, before_lines.len().to_string().white().bold());
    println!("  After:  {} ({} rules/lines)", after, after_lines.len().to_string().white().bold());

    // Build normalized maps
    let before_set: HashSet<String> = before_lines.iter().map(|l| normalize_line(l)).collect();
    let after_set: HashSet<String> = after_lines.iter().map(|l| normalize_line(l)).collect();

    let before_map: HashMap<String, String> = before_lines
        .iter()
        .map(|l| (normalize_line(l), l.clone()))
        .collect();

    let after_map: HashMap<String, String> = after_lines
        .iter()
        .map(|l| (normalize_line(l), l.clone()))
        .collect();

    let mut findings: Vec<DiffFinding> = Vec::new();

    // Find removed lines
    for norm in &before_set {
        if !after_set.contains(norm) {
            let original = before_map.get(norm).unwrap();
            let key = extract_rule_key(original);
            let impact = assess_security_impact(original, "", "REMOVED");

            findings.push(DiffFinding {
                change_type: "➖ REMOVED".to_string(),
                identifier: key,
                before: truncate(original, 50),
                after: "—".to_string(),
                impact,
            });
        }
    }

    // Find added lines
    for norm in &after_set {
        if !before_set.contains(norm) {
            let original = after_map.get(norm).unwrap();
            let key = extract_rule_key(original);
            let impact = assess_security_impact("", original, "ADDED");

            findings.push(DiffFinding {
                change_type: "➕ ADDED".to_string(),
                identifier: key,
                before: "—".to_string(),
                after: truncate(original, 50),
                impact,
            });
        }
    }

    // Try to find modifications by matching rule keys
    let before_keyed: HashMap<String, &String> = before_lines
        .iter()
        .map(|l| (extract_rule_key(l).to_lowercase(), l))
        .collect();
    let after_keyed: HashMap<String, &String> = after_lines
        .iter()
        .map(|l| (extract_rule_key(l).to_lowercase(), l))
        .collect();

    for (key, before_line) in &before_keyed {
        if let Some(after_line) = after_keyed.get(key) {
            let norm_b = normalize_line(before_line);
            let norm_a = normalize_line(after_line);
            if norm_b != norm_a {
                let impact = assess_security_impact(before_line, after_line, "MODIFIED");

                // Check if this is already captured as add/remove
                let already_found = findings.iter().any(|f| {
                    f.identifier.to_lowercase() == *key
                        && (f.change_type.contains("REMOVED") || f.change_type.contains("ADDED"))
                });

                if !already_found {
                    findings.push(DiffFinding {
                        change_type: "✏️ MODIFIED".to_string(),
                        identifier: key.clone(),
                        before: truncate(before_line, 50),
                        after: truncate(after_line, 50),
                        impact,
                    });
                }
            }
        }
    }

    // Sort by impact severity
    findings.sort_by(|a, b| {
        let impact_order = |s: &str| -> u8 {
            if s.contains("CRITICAL") { 0 }
            else if s.contains("HIGH") { 1 }
            else if s.contains("IMPROVED") { 4 }
            else if s.contains("MEDIUM") { 2 }
            else { 3 }
        };
        impact_order(&a.impact).cmp(&impact_order(&b.impact))
    });

    // Display
    let added = findings.iter().filter(|f| f.change_type.contains("ADDED")).count();
    let removed = findings.iter().filter(|f| f.change_type.contains("REMOVED")).count();
    let modified = findings.iter().filter(|f| f.change_type.contains("MODIFIED")).count();
    let regressions = findings.iter().filter(|f| {
        f.impact.contains("CRITICAL") || f.impact.contains("HIGH")
    }).count();

    println!("\n{}", "📊 Diff Summary".green().bold());
    let summary = vec![
        DiffSummary { metric: "Added".to_string(), value: format!("{}", added) },
        DiffSummary { metric: "Removed".to_string(), value: format!("{}", removed) },
        DiffSummary { metric: "Modified".to_string(), value: format!("{}", modified) },
        DiffSummary {
            metric: "Security Regressions".to_string(),
            value: if regressions > 0 {
                format!("⚠ {}", regressions)
            } else {
                "✅ 0".to_string()
            },
        },
    ];
    let summary_table = Table::new(&summary).to_string();
    println!("{}", summary_table);

    if findings.is_empty() {
        println!("\n  {} Configs are identical (after normalization).", "✅".green());
    } else {
        println!("\n{}", "🔍 Detailed Changes".yellow().bold());
        let display: Vec<&DiffFinding> = findings.iter().take(50).collect();
        let table = Table::new(&display).to_string();
        println!("{}", table);

        if findings.len() > 50 {
            println!("  ... and {} more changes (export to JSON for full list)", findings.len() - 50);
        }
    }

    // Export
    if let Some(out_path) = output {
        let report = DiffReport {
            file_before: before.to_string(),
            file_after: after.to_string(),
            total_rules_before: before_lines.len(),
            total_rules_after: after_lines.len(),
            added,
            removed,
            modified,
            security_regressions: regressions,
            findings,
        };
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(out_path, &json)
            .with_context(|| format!("Failed to write report: {}", out_path))?;
        println!("\n{} Report exported to {}", "📁".green(), out_path.white().bold());
    }

    println!("\n{}", "✅ Config diff complete.".green().bold());
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
