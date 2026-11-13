use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tabled::{Table, Tabled};

#[derive(Debug, Deserialize, Clone)]
pub struct FirewallRule {
    #[serde(alias = "Rule Name", alias = "rule_name", alias = "name", alias = "Name")]
    pub name: Option<String>,
    #[serde(alias = "Source", alias = "source", alias = "src", alias = "Src")]
    pub source: String,
    #[serde(alias = "Destination", alias = "destination", alias = "dst", alias = "Dst")]
    pub destination: String,
    #[serde(alias = "Service", alias = "service", alias = "port", alias = "Port")]
    pub service: String,
    #[serde(alias = "Action", alias = "action")]
    pub action: String,
    #[serde(alias = "Enabled", alias = "enabled", alias = "Status", alias = "status")]
    pub enabled: Option<String>,
    #[serde(alias = "Zone From", alias = "zone_from", alias = "src_zone")]
    pub zone_from: Option<String>,
    #[serde(alias = "Zone To", alias = "zone_to", alias = "dst_zone")]
    pub zone_to: Option<String>,
    #[serde(alias = "Log", alias = "log", alias = "Logging")]
    pub log: Option<String>,
}

#[derive(Debug, Serialize, Tabled, Clone)]
pub struct AuditFinding {
    #[tabled(rename = "Rule")]
    pub rule_name: String,
    #[tabled(rename = "Risk")]
    pub risk_level: String,
    #[tabled(rename = "Score")]
    pub risk_score: u8,
    #[tabled(rename = "Issue")]
    pub issue: String,
    #[tabled(rename = "Recommendation")]
    pub recommendation: String,
}

#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub total_rules: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub findings: Vec<AuditFinding>,
    pub summary: HashMap<String, usize>,
}

fn audit_rule(rule: &FirewallRule, index: usize) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let rule_name = rule
        .name
        .clone()
        .unwrap_or_else(|| format!("Rule #{}", index + 1));

    let src = rule.source.trim().to_lowercase();
    let dst = rule.destination.trim().to_lowercase();
    let svc = rule.service.trim().to_lowercase();
    let action = rule.action.trim().to_lowercase();

    // Check 1: any-any-any-allow (most critical)
    if (src == "any" || src == "0.0.0.0/0" || src == "*")
        && (dst == "any" || dst == "0.0.0.0/0" || dst == "*")
        && (svc == "any" || svc == "application-default" || svc == "*")
        && (action == "allow" || action == "permit" || action == "accept")
    {
        findings.push(AuditFinding {
            rule_name: rule_name.clone(),
            risk_level: "CRITICAL".to_string(),
            risk_score: 10,
            issue: "Any-Any-Any ALLOW — completely open rule".to_string(),
            recommendation: "Remove or restrict source, destination, and service".to_string(),
        });
    }

    // Check 2: any source with allow
    if (src == "any" || src == "0.0.0.0/0" || src == "*")
        && (action == "allow" || action == "permit" || action == "accept")
        && !(dst == "any" || dst == "0.0.0.0/0")
    {
        findings.push(AuditFinding {
            rule_name: rule_name.clone(),
            risk_level: "HIGH".to_string(),
            risk_score: 8,
            issue: "Source is ANY — allows traffic from all origins".to_string(),
            recommendation: "Restrict source to specific IPs or subnets".to_string(),
        });
    }

    // Check 3: any destination with allow
    if (dst == "any" || dst == "0.0.0.0/0" || dst == "*")
        && (action == "allow" || action == "permit" || action == "accept")
        && !(src == "any" || src == "0.0.0.0/0")
    {
        findings.push(AuditFinding {
            rule_name: rule_name.clone(),
            risk_level: "HIGH".to_string(),
            risk_score: 7,
            issue: "Destination is ANY — allows traffic to all targets".to_string(),
            recommendation: "Restrict destination to specific IPs or subnets".to_string(),
        });
    }

    // Check 4: any service with allow
    if (svc == "any" || svc == "*")
        && (action == "allow" || action == "permit" || action == "accept")
    {
        findings.push(AuditFinding {
            rule_name: rule_name.clone(),
            risk_level: "MEDIUM".to_string(),
            risk_score: 6,
            issue: "Service is ANY — all ports/protocols allowed".to_string(),
            recommendation: "Restrict to specific services/ports needed".to_string(),
        });
    }

    // Check 5: risky ports open
    let risky_ports = [
        ("21", "FTP"),
        ("23", "Telnet"),
        ("445", "SMB"),
        ("3389", "RDP"),
        ("1433", "MSSQL"),
        ("3306", "MySQL"),
        ("5432", "PostgreSQL"),
        ("6379", "Redis"),
        ("27017", "MongoDB"),
        ("22", "SSH"),
    ];

    for (port, service_name) in &risky_ports {
        if svc.contains(port)
            && (action == "allow" || action == "permit" || action == "accept")
            && (src == "any" || src == "0.0.0.0/0" || src == "*")
        {
            findings.push(AuditFinding {
                rule_name: rule_name.clone(),
                risk_level: "HIGH".to_string(),
                risk_score: 8,
                issue: format!("{} ({}) open from ANY source", service_name, port),
                recommendation: format!(
                    "Restrict {} access to specific management IPs only",
                    service_name
                ),
            });
        }
    }

    // Check 6: logging disabled
    if let Some(ref log) = rule.log {
        let log_lower = log.trim().to_lowercase();
        if log_lower == "no" || log_lower == "disabled" || log_lower == "false" || log_lower == "0"
        {
            findings.push(AuditFinding {
                rule_name: rule_name.clone(),
                risk_level: "LOW".to_string(),
                risk_score: 3,
                issue: "Logging is disabled on this rule".to_string(),
                recommendation: "Enable logging for audit trail and incident response".to_string(),
            });
        }
    }

    // Check 7: disabled rule still present
    if let Some(ref enabled) = rule.enabled {
        let en = enabled.trim().to_lowercase();
        if en == "no" || en == "disabled" || en == "false" || en == "0" {
            findings.push(AuditFinding {
                rule_name: rule_name.clone(),
                risk_level: "LOW".to_string(),
                risk_score: 2,
                issue: "Rule is disabled but still in the ruleset".to_string(),
                recommendation: "Remove disabled rules to reduce clutter and confusion".to_string(),
            });
        }
    }

    findings
}

pub fn run(input: &str, _format: &str, output: Option<&str>, min_risk: u8) -> Result<()> {
    println!(
        "{} {}",
        "🛡️  Auditing firewall rules from:".green().bold(),
        input.yellow()
    );
    println!();

    let content =
        fs::read_to_string(input).with_context(|| format!("Failed to read file: {}", input))?;

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());

    let mut rules: Vec<FirewallRule> = Vec::new();
    for result in reader.deserialize() {
        match result {
            Ok(rule) => rules.push(rule),
            Err(e) => eprintln!("{} Skipping malformed row: {}", "⚠".yellow(), e),
        }
    }

    if rules.is_empty() {
        println!("{}", "No rules found in the file.".yellow());
        return Ok(());
    }

    println!("  📋 Total rules loaded: {}", rules.len().to_string().cyan());

    let bar = indicatif::ProgressBar::new(rules.len() as u64);
    bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("  Auditing [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let mut all_findings: Vec<AuditFinding> = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let findings = audit_rule(rule, i);
        for f in findings {
            if f.risk_score >= min_risk {
                all_findings.push(f);
            }
        }
        bar.inc(1);
    }
    bar.finish_and_clear();

    // Sort by risk score descending
    all_findings.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    let critical = all_findings.iter().filter(|f| f.risk_score >= 9).count();
    let high = all_findings
        .iter()
        .filter(|f| f.risk_score >= 7 && f.risk_score < 9)
        .count();
    let medium = all_findings
        .iter()
        .filter(|f| f.risk_score >= 4 && f.risk_score < 7)
        .count();
    let low = all_findings
        .iter()
        .filter(|f| f.risk_score < 4)
        .count();

    println!();
    println!("  {}", "━━━ AUDIT SUMMARY ━━━".white().bold());
    println!(
        "  {} {}",
        "🔴 Critical:".red().bold(),
        critical.to_string().red().bold()
    );
    println!(
        "  {} {}",
        "🟠 High:    ".yellow().bold(),
        high.to_string().yellow().bold()
    );
    println!(
        "  {} {}",
        "🟡 Medium:  ".bright_yellow().bold(),
        medium.to_string().bright_yellow()
    );
    println!(
        "  {} {}",
        "🟢 Low:     ".green().bold(),
        low.to_string().green()
    );
    println!(
        "  {} {}",
        "📊 Total findings:".white().bold(),
        all_findings.len()
    );
    println!();

    if !all_findings.is_empty() {
        let table = Table::new(&all_findings).to_string();
        println!("{}", table);
    } else {
        println!(
            "  {} No findings above risk score {}.",
            "✅".green(),
            min_risk
        );
    }

    // Export if requested
    if let Some(output_path) = output {
        let mut summary = HashMap::new();
        summary.insert("critical".to_string(), critical);
        summary.insert("high".to_string(), high);
        summary.insert("medium".to_string(), medium);
        summary.insert("low".to_string(), low);

        let report = AuditReport {
            total_rules: rules.len(),
            total_findings: all_findings.len(),
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            findings: all_findings,
            summary,
        };

        let json =
            serde_json::to_string_pretty(&report).context("Failed to serialize audit report")?;
        fs::write(output_path, &json)
            .with_context(|| format!("Failed to write report to: {}", output_path))?;

        println!(
            "\n  {} Report exported to: {}",
            "📁".green(),
            output_path.yellow()
        );
    }

    Ok(())
}
