#[allow(unused_imports, unused_variables, dead_code, clippy::needless_return)]
use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tabled::{Table, Tabled};

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DnsEntry {
    #[serde(alias = "Timestamp", alias = "timestamp", alias = "time", alias = "Time")]
    timestamp: Option<String>,
    #[serde(alias = "Source", alias = "source", alias = "src_ip", alias = "Client", alias = "client")]
    source: Option<String>,
    #[serde(alias = "Query", alias = "query", alias = "domain", alias = "Domain", alias = "Name", alias = "name")]
    query: String,
    #[serde(alias = "Type", alias = "type", alias = "qtype", alias = "QType", alias = "record_type")]
    query_type: Option<String>,
    #[serde(alias = "Response", alias = "response", alias = "answer", alias = "Answer", alias = "rdata")]
    response: Option<String>,
    #[serde(alias = "Action", alias = "action", alias = "status", alias = "Status")]
    action: Option<String>,
}

#[derive(Debug, Serialize, Tabled)]
struct DgaSuspect {
    #[tabled(rename = "Domain")]
    domain: String,
    #[tabled(rename = "Entropy")]
    entropy: String,
    #[tabled(rename = "Length")]
    length: usize,
    #[tabled(rename = "Consonant %")]
    consonant_pct: String,
    #[tabled(rename = "Risk")]
    risk: String,
}

#[derive(Debug, Serialize, Tabled)]
struct TunnelSuspect {
    #[tabled(rename = "Domain")]
    domain: String,
    #[tabled(rename = "Subdomain Len")]
    subdomain_length: usize,
    #[tabled(rename = "Unique Subs")]
    unique_subdomains: usize,
    #[tabled(rename = "TXT Queries")]
    txt_count: usize,
    #[tabled(rename = "Reason")]
    reason: String,
}

#[derive(Debug, Serialize, Tabled)]
struct TopQueried {
    #[tabled(rename = "Domain")]
    domain: String,
    #[tabled(rename = "Queries")]
    count: usize,
    #[tabled(rename = "Unique Clients")]
    unique_clients: usize,
}

#[derive(Debug, Serialize)]
struct DnsReport {
    total_queries: usize,
    unique_domains: usize,
    dga_suspects: Vec<DgaSuspect>,
    tunnel_suspects: Vec<TunnelSuspect>,
    top_queried: Vec<TopQueried>,
}

/// Calculate Shannon entropy of a string
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Calculate consonant percentage (high consonant % = likely DGA)
fn consonant_percentage(s: &str) -> f64 {
    let consonants = "bcdfghjklmnpqrstvwxyz";
    let alpha_chars: Vec<char> = s.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if alpha_chars.is_empty() {
        return 0.0;
    }
    let consonant_count = alpha_chars
        .iter()
        .filter(|c| consonants.contains(c.to_ascii_lowercase()))
        .count();
    (consonant_count as f64 / alpha_chars.len() as f64) * 100.0
}

/// Extract registrable domain (simplified: last two parts)
fn extract_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    }
}

/// Extract subdomain part
fn extract_subdomain(domain: &str) -> String {
    let parts: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if parts.len() > 2 {
        parts[..parts.len() - 2].join(".")
    } else {
        String::new()
    }
}

/// Check if domain looks like DGA
fn is_dga_suspect(domain: &str) -> bool {
    let base = extract_base_domain(domain);
    let label = base.split('.').next().unwrap_or("");

    // Skip very short labels or known safe patterns
    if label.len() < 6 {
        return false;
    }

    let entropy = shannon_entropy(label);
    let consonant_pct = consonant_percentage(label);
    let has_no_vowels = !label.chars().any(|c| "aeiou".contains(c.to_ascii_lowercase()));
    let digit_ratio = label.chars().filter(|c| c.is_ascii_digit()).count() as f64 / label.len() as f64;

    // High entropy + high consonant ratio + digits mixed = DGA
    (entropy > 3.5 && consonant_pct > 70.0)
        || (entropy > 3.8 && digit_ratio > 0.3)
        || (has_no_vowels && label.len() > 8)
        || (entropy > 4.0 && label.len() > 12)
}

fn risk_from_entropy(entropy: f64, consonant_pct: f64, length: usize) -> String {
    let score = if entropy > 4.2 && consonant_pct > 75.0 { 3 }
    else if entropy > 3.8 && length > 15 { 3 }
    else if entropy > 3.5 { 2 }
    else { 1 };

    match score {
        3 => "🔴 HIGH".to_string(),
        2 => "🟡 MEDIUM".to_string(),
        _ => "🟢 LOW".to_string(),
    }
}

pub fn run(input: &str, output: Option<&str>, top: usize) -> Result<()> {
    println!("{}", "🔍 DNS Log Analyzer".cyan().bold());
    println!("{}", "=".repeat(60).dimmed());

    let content = fs::read_to_string(input)
        .with_context(|| format!("Failed to read DNS log: {}", input))?;

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(content.as_bytes());

    let entries: Vec<DnsEntry> = reader
        .deserialize()
        .filter_map(|r| r.ok())
        .collect();

    if entries.is_empty() {
        println!("{}", "⚠ No DNS entries found in file.".yellow());
        return Ok(());
    }

    let total = entries.len();
    let unique_domains: std::collections::HashSet<String> = entries
        .iter()
        .map(|e| extract_base_domain(&e.query))
        .collect();

    println!("\n{}", "📊 DNS Log Summary".green().bold());
    println!("  Total queries:    {}", total.to_string().white().bold());
    println!("  Unique domains:   {}", unique_domains.len().to_string().white().bold());

    // === DGA Detection ===
    println!("\n{}", "🎯 DGA Domain Detection".yellow().bold());

    let mut dga_suspects: Vec<DgaSuspect> = Vec::new();
    let mut seen_dga: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in &entries {
        let base = extract_base_domain(&entry.query);
        let label = base.split('.').next().unwrap_or("").to_string();

        if seen_dga.contains(&base) || !is_dga_suspect(&entry.query) {
            continue;
        }
        seen_dga.insert(base.clone());

        let entropy = shannon_entropy(&label);
        let cpct = consonant_percentage(&label);

        dga_suspects.push(DgaSuspect {
            domain: base.clone(),
            entropy: format!("{:.2}", entropy),
            length: label.len(),
            consonant_pct: format!("{:.0}%", cpct),
            risk: risk_from_entropy(entropy, cpct, label.len()),
        });
    }

    dga_suspects.sort_by(|a, b| b.entropy.partial_cmp(&a.entropy).unwrap());
    let dga_display: Vec<&DgaSuspect> = dga_suspects.iter().take(top).collect();

    if dga_display.is_empty() {
        println!("  {} No DGA-like domains detected.", "✅".green());
    } else {
        println!("  {} {} suspicious domains found!\n", "⚠".red(), dga_suspects.len());
        let table = Table::new(&dga_display).to_string();
        println!("{}", table);
    }

    // === DNS Tunneling Detection ===
    println!("\n{}", "🕳️ DNS Tunneling Detection".yellow().bold());

    let mut domain_subdomains: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut domain_txt_count: HashMap<String, usize> = HashMap::new();

    for entry in &entries {
        let base = extract_base_domain(&entry.query);
        let sub = extract_subdomain(&entry.query);

        if !sub.is_empty() {
            domain_subdomains
                .entry(base.clone())
                .or_default()
                .insert(sub);
        }

        if let Some(qtype) = &entry.query_type {
            if qtype.to_uppercase() == "TXT" || qtype == "16" {
                *domain_txt_count.entry(base).or_insert(0) += 1;
            }
        }
    }

    let mut tunnel_suspects: Vec<TunnelSuspect> = Vec::new();

    for (domain, subs) in &domain_subdomains {
        let txt_count = domain_txt_count.get(domain).copied().unwrap_or(0);
        let max_sub_len = subs.iter().map(|s| s.len()).max().unwrap_or(0);
        let avg_sub_len = if subs.is_empty() {
            0
        } else {
            subs.iter().map(|s| s.len()).sum::<usize>() / subs.len()
        };

        let mut reasons = Vec::new();

        if subs.len() > 20 {
            reasons.push("Many unique subdomains");
        }
        if max_sub_len > 50 {
            reasons.push("Very long subdomain labels");
        }
        if avg_sub_len > 30 {
            reasons.push("High avg subdomain length");
        }
        if txt_count > 10 {
            reasons.push("Excessive TXT queries");
        }

        if !reasons.is_empty() {
            tunnel_suspects.push(TunnelSuspect {
                domain: domain.clone(),
                subdomain_length: max_sub_len,
                unique_subdomains: subs.len(),
                txt_count,
                reason: reasons.join("; "),
            });
        }
    }

    tunnel_suspects.sort_by(|a, b| b.unique_subdomains.cmp(&a.unique_subdomains));
    let tunnel_display: Vec<&TunnelSuspect> = tunnel_suspects.iter().take(top).collect();

    if tunnel_display.is_empty() {
        println!("  {} No DNS tunneling indicators found.", "✅".green());
    } else {
        println!("  {} {} domains show tunneling indicators!\n", "⚠".red(), tunnel_suspects.len());
        let table = Table::new(&tunnel_display).to_string();
        println!("{}", table);
    }

    // === Top Queried Domains ===
    println!("\n{}", "📈 Top Queried Domains".green().bold());

    let mut domain_counts: HashMap<String, (usize, std::collections::HashSet<String>)> = HashMap::new();
    for entry in &entries {
        let base = extract_base_domain(&entry.query);
        let client = entry.source.clone().unwrap_or_else(|| "unknown".to_string());
        let entry_data = domain_counts.entry(base).or_insert_with(|| (0, std::collections::HashSet::new()));
        entry_data.0 += 1;
        entry_data.1.insert(client);
    }

    let mut top_queried: Vec<TopQueried> = domain_counts
        .into_iter()
        .map(|(domain, (count, clients))| TopQueried {
            domain,
            count,
            unique_clients: clients.len(),
        })
        .collect();

    top_queried.sort_by(|a, b| b.count.cmp(&a.count));
    let top_display: Vec<&TopQueried> = top_queried.iter().take(top).collect();

    let table = Table::new(&top_display).to_string();
    println!("{}", table);

    // === Export ===
    if let Some(out_path) = output {
        let report = DnsReport {
            total_queries: total,
            unique_domains: unique_domains.len(),
            dga_suspects,
            tunnel_suspects,
            top_queried,
        };
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(out_path, &json)
            .with_context(|| format!("Failed to write report: {}", out_path))?;
        println!("\n{} Report exported to {}", "📁".green(), out_path.white().bold());
    }

    println!("\n{}", "✅ DNS analysis complete.".green().bold());
    Ok(())
}
