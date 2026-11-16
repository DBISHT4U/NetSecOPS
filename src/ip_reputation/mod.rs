#[allow(unused_imports, unused_variables, dead_code, clippy::needless_return, clippy::match_single_binding, clippy::match_wildcard_for_single_variants)]
use anyhow::{Context, Result};
use colored::*;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use tabled::{Table, Tabled};

/// Known malicious IP ranges and indicators (built-in baseline)
/// In production, these would be loaded from threat intelligence feeds
const BOGON_RANGES: &[&str] = &[
    "0.", "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "192.168.", "224.", "240.", "255.",
];

/// Suspicious port patterns when found in threat context
const SUSPICIOUS_PORTS: &[u16] = &[
    4444, 5555, 6666, 6667, 6668, 6669, // C2 / IRC
    1080, 3128, 8080, 8888, 9050, 9150, // Proxy / Tor
    31337, 12345, 65535,                  // Backdoor classics
];

#[derive(Debug, Serialize, Tabled, Clone)]
struct IpFinding {
    #[tabled(rename = "IP Address")]
    ip: String,
    #[tabled(rename = "Category")]
    category: String,
    #[tabled(rename = "Risk")]
    risk: String,
    #[tabled(rename = "Details")]
    details: String,
}

#[derive(Debug, Serialize, Tabled)]
struct IpSummary {
    #[tabled(rename = "Category")]
    category: String,
    #[tabled(rename = "Count")]
    count: usize,
}

#[derive(Debug, Serialize)]
struct IpReport {
    total_checked: usize,
    valid_ips: usize,
    flagged: usize,
    findings: Vec<IpFinding>,
    summary: Vec<IpSummary>,
}

fn is_bogon(ip: &str) -> bool {
    BOGON_RANGES.iter().any(|prefix| ip.starts_with(prefix))
}

fn is_valid_ip(ip: &str) -> bool {
    ip.trim().parse::<IpAddr>().is_ok()
}

fn reverse_dns_heuristic(ip: &str) -> Option<String> {
    // Heuristic: IPs in certain ranges are commonly associated with threats
    // This is a simplified offline check
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return None;
    }

    // Check for IPs that are commonly in threat feeds (simplified patterns)
    // Placeholder for future threat feed integration
    let _first: Option<u8> = octets[0].parse().ok();
    None
}

fn check_ip_against_threatlist(ip: &str, threat_ips: &HashSet<String>) -> Vec<IpFinding> {
    let mut findings = Vec::new();

    // Check against user-provided threat list
    if threat_ips.contains(ip) {
        findings.push(IpFinding {
            ip: ip.to_string(),
            category: "Threat Intel Match".to_string(),
            risk: "🔴 CRITICAL".to_string(),
            details: "IP found in provided threat intelligence feed".to_string(),
        });
    }

    // Check bogon
    if is_bogon(ip) {
        findings.push(IpFinding {
            ip: ip.to_string(),
            category: "Bogon/RFC1918".to_string(),
            risk: "🟡 INFO".to_string(),
            details: "Private/reserved IP range — should not appear in external traffic".to_string(),
        });
    }

    // Check for suspicious patterns
    let octets: Vec<u8> = ip.split('.')
        .filter_map(|o| o.parse().ok())
        .collect();

    if octets.len() == 4 {
        // Sequential octets (e.g., 1.2.3.4) — often scanner/test IPs
        if octets[0] + 1 == octets[1] && octets[1] + 1 == octets[2] && octets[2] + 1 == octets[3] {
            findings.push(IpFinding {
                ip: ip.to_string(),
                category: "Suspicious Pattern".to_string(),
                risk: "🟡 MEDIUM".to_string(),
                details: "Sequential octets — often scanner or test traffic".to_string(),
            });
        }

        // Same octet repeated (e.g., 6.6.6.6)
        if octets[0] == octets[1] && octets[1] == octets[2] && octets[2] == octets[3] && octets[0] != 0 {
            findings.push(IpFinding {
                ip: ip.to_string(),
                category: "Suspicious Pattern".to_string(),
                risk: "🟡 LOW".to_string(),
                details: "Repeating octets — uncommon in legitimate traffic".to_string(),
            });
        }
    }

    if let Some(info) = reverse_dns_heuristic(ip) {
        findings.push(IpFinding {
            ip: ip.to_string(),
            category: "DNS Heuristic".to_string(),
            risk: "🟡 MEDIUM".to_string(),
            details: info,
        });
    }

    findings
}

pub fn run(input: &str, threat_feed: Option<&str>, output: Option<&str>) -> Result<()> {
    println!("{}", "🔎 IP Reputation Checker".cyan().bold());
    println!("{}", "=".repeat(60).dimmed());

    // Load IPs to check
    let content = fs::read_to_string(input)
        .with_context(|| format!("Failed to read IP list: {}", input))?;

    let ips: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    println!("  Loaded {} IPs from {}", ips.len().to_string().white().bold(), input);

    // Load optional threat feed
    let threat_ips: HashSet<String> = if let Some(feed_path) = threat_feed {
        let feed_content = fs::read_to_string(feed_path)
            .with_context(|| format!("Failed to read threat feed: {}", feed_path))?;
        let set: HashSet<String> = feed_content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        println!("  Loaded {} IPs from threat feed: {}", set.len().to_string().white().bold(), feed_path);
        set
    } else {
        println!("  {} No external threat feed provided (using built-in checks only)", "ℹ".blue());
        HashSet::new()
    };

    // Validate IPs
    let valid_ips: Vec<&String> = ips.iter().filter(|ip| is_valid_ip(ip)).collect();
    let invalid_count = ips.len() - valid_ips.len();

    if invalid_count > 0 {
        println!("  {} {} invalid IPs skipped", "⚠".yellow(), invalid_count);
    }

    // Run checks
    println!("\n{}", "🔍 Checking IPs...".green().bold());

    let mut all_findings: Vec<IpFinding> = Vec::new();
    let mut category_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for ip in &valid_ips {
        let findings = check_ip_against_threatlist(ip, &threat_ips);
        for f in &findings {
            *category_counts.entry(f.category.clone()).or_insert(0) += 1;
        }
        all_findings.extend(findings);
    }

    // Display results
    if all_findings.is_empty() {
        println!("\n  {} All {} IPs appear clean!", "✅".green(), valid_ips.len());
    } else {
        // Sort by risk (CRITICAL first)
        all_findings.sort_by(|a, b| {
            let risk_order = |r: &str| -> u8 {
                if r.contains("CRITICAL") { 0 }
                else if r.contains("HIGH") { 1 }
                else if r.contains("MEDIUM") { 2 }
                else { 3 }
            };
            risk_order(&a.risk).cmp(&risk_order(&b.risk))
        });

        println!("\n  {} {} findings across {} IPs\n",
            "⚠".red(),
            all_findings.len().to_string().red().bold(),
            valid_ips.len()
        );

        let table = Table::new(&all_findings).to_string();
        println!("{}", table);

        // Summary table
        println!("\n{}", "📊 Summary by Category".green().bold());
        let summary: Vec<IpSummary> = category_counts
            .into_iter()
            .map(|(category, count)| IpSummary { category, count })
            .collect();
        let summary_table = Table::new(&summary).to_string();
        println!("{}", summary_table);
    }

    // Export
    if let Some(out_path) = output {
        let summary: Vec<IpSummary> = all_findings
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, f| {
                *acc.entry(f.category.clone()).or_insert(0usize) += 1;
                acc
            })
            .into_iter()
            .map(|(category, count)| IpSummary { category, count })
            .collect();

        let report = IpReport {
            total_checked: ips.len(),
            valid_ips: valid_ips.len(),
            flagged: all_findings.len(),
            findings: all_findings,
            summary,
        };
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(out_path, &json)
            .with_context(|| format!("Failed to write report: {}", out_path))?;
        println!("\n{} Report exported to {}", "📁".green(), out_path.white().bold());
    }

    println!("\n{}", "✅ IP reputation check complete.".green().bold());
    Ok(())
}
