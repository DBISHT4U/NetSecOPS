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
    let rule_name = rule.name.clone().unwrap_or_else(|| format!("Rule #{}", index + 1));
    let src = rule.source.trim().to_lowercase();
    let dst = rule.destination.trim().to_lowercase();
    let svc = rule.service.trim().to_lowercase();
    let action = rule.action.trim().to_lowercase();
    let is_allow = action == "allow" || action == "permit" || action == "accept";
    let src_any = src == "any" || src == "0.0.0.0/0" || src == "*";
    let dst_any = dst == "any" || dst == "0.0.0.0/0" || dst == "*";
    let svc_any = svc == "any" || svc == "application-default" || svc == "*";

    if src_any && dst_any && svc_any && is_allow {
        findings.push(AuditFinding {
            rule_name: rule_name.clone(),
            risk_level: "CRITICAL".to_string(),
            risk_score: 10,
            issue: "Any-Any-Any ALLOW rule".to_string(),
            recommendation: "Remove or restrict source, destination, and service".to_string(),
        });
    }

    if src_any && is_allow && !dst_any {
        findings.push(AuditFinding {
            rule_name: rule_name.clone(),
            risk_level: "HIGH".to_string(),
            risk_score: 8,
            issue: "Source is ANY — allows traffic from all origins".to_string(),
            recommendation: "Restrict source to specific IPs or subnets".to_string(),
        });
    }

    if dst_any && is_allow && !src_any {
        findings.push(AuditFinding {
            rule_name: rule_name.clone(),
            risk_level: "HIGH".to_string(),
            risk_score: 7,
            issue: "Destination is ANY — allows traffic to all targets".to_string(),
            recommendation: "Restrict destination to specific IPs or subnets".to_string(),
        });
    }

    if (svc == "any" || svc == "*") && is_allow {
        findings.push(AuditFinding {
            rule_name: rule_name.clone(),
            risk_level: "MEDIUM".to_string(),
            risk_score: 6,
            issue: "Service is ANY — all ports/protocols allowed".to_string(),
            recommendation: "Restrict to specific services/ports needed".to_string(),
        });
    }

    let risky_ports: &[(&str, &str)] = &[
        ("21", "FTP"), ("23", "Telnet"), ("445", "SMB"), ("3389", "RDP"),
        ("1433", "MSSQL"), ("3306", "MySQL"), ("5432", "PostgreSQL"),
        ("6379", "Redis"), ("27017", "MongoDB"), ("22", "SSH"),
    ];

    for &(port, service_name) in risky_ports {
        if svc.contains(port) && is_allow && src_any {
            findings.push(AuditFinding {
                rule_name: rule_name.clone(),
                risk_level: "HIGH".to_string(),
                risk_score: 8,
                issue: format!("{} ({}) open from ANY source", service_name, port),
                recommendation: format!("Restrict {} access to specific management IPs", service_name),
            });
        }
    }

    if let Some(ref log) = rule.log {
        let log_lower = log.trim().to_lowercase();
        if log_lower == "no" || log_lower == "disabled" || log_lower == "false" || log_lower == "0" {
            findings.push(AuditFinding {
                rule_name: rule_name.clone(),
                risk_level: "LOW".to_string(),
                risk_score: 3,
                issue: "Logging is disabled on this rule".to_string(),
                recommendation: "Enable logging for audit trail and incident response".to_string(),
            });
        }
    }

    if let Some(ref enabled) = rule.enabled {
        let en = enabled.trim().to_lowercase();
        if en == "no" || en == "disabled" || en == "false" || en == "0" {
            findings.push(AuditFinding {
                rule_name: rule_name.clone(),
                risk_level: "LOW".to_string(),
                risk_score: 2,
                issue: "Rule is disabled but still in the ruleset".to_string(),
                recommendation: "Remove disabled rules to reduce clutter".to_string(),
            });
        }
    }

    findings
}

pub fn run(input: &str, _format: &str, output: Option<&str>, min_risk: u8) -> Result<()> {
    println!("{} {}", "Auditing firewall rules from:".green().bold(), input.yellow());
    println!();

    let content = fs::read_to_string(input).with_context(|| format!("Failed to read file: {}", input))?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());

    let mut rules: Vec<FirewallRule> = Vec::new();
    for result in reader.deserialize() {
        match result {
            Ok(rule) => rules.push(rule),
            Err(e) => eprintln!("{} Skipping malformed row: {}", "Warning:".yellow(), e),
        }
    }

    if rules.is_empty() {
        println!("{}", "No rules found in the file.".yellow());
        return Ok(());
    }

    println!("  Total rules loaded: {}", rules.len().to_string().cyan());

    let bar = indicatif::ProgressBar::new(rules.len() as u64);
    bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("  Auditing [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("##-"),
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

    all_findings.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    let critical = all_findings.iter().filter(|f| f.risk_score >= 9).count();
    let high = all_findings.iter().filter(|f| f.risk_score >= 7 && f.risk_score < 9).count();
    let medium = all_findings.iter().filter(|f| f.risk_score >= 4 && f.risk_score < 7).count();
    let low = all_findings.iter().filter(|f| f.risk_score < 4).count();

    println!();
    println!("  {}", "--- AUDIT SUMMARY ---".white().bold());
    println!("  Critical: {}", critical.to_string().red().bold());
    println!("  High:     {}", high.to_string().yellow().bold());
    println!("  Medium:   {}", medium.to_string().bright_yellow());
    println!("  Low:      {}", low.to_string().green());
    println!("  Total findings: {}", all_findings.len());
    println!();

    if !all_findings.is_empty() {
        let table = Table::new(&all_findings).to_string();
        println!("{}", table);
    } else {
        println!("  No findings above risk score {}.", min_risk);
    }

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

        let json = serde_json::to_string_pretty(&report).context("Failed to serialize")?;
        fs::write(output_path, &json)
            .with_context(|| format!("Failed to write report to: {}", output_path))?;
        println!("\n  Report exported to: {}", output_path.yellow());
    }

    Ok(())
}
