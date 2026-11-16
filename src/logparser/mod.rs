use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tabled::{Table, Tabled};

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct LogEntry {
    #[serde(alias = "Timestamp", alias = "timestamp", alias = "date", alias = "Date")]
    pub timestamp: Option<String>,
    #[serde(alias = "User", alias = "user", alias = "username", alias = "Username")]
    pub user: Option<String>,
    #[serde(alias = "Source IP", alias = "source_ip", alias = "src_ip", alias = "ClientIP")]
    pub source_ip: Option<String>,
    #[serde(alias = "URL", alias = "url", alias = "Url", alias = "request_url")]
    pub url: Option<String>,
    #[serde(alias = "Domain", alias = "domain", alias = "host", alias = "Host")]
    pub domain: Option<String>,
    #[serde(alias = "Action", alias = "action", alias = "status", alias = "Status")]
    pub action: Option<String>,
    #[serde(alias = "Category", alias = "category", alias = "url_category")]
    pub category: Option<String>,
    #[serde(alias = "Bytes", alias = "bytes", alias = "size", alias = "Size")]
    pub bytes: Option<u64>,
    #[serde(alias = "Method", alias = "method")]
    pub method: Option<String>,
}

#[derive(Debug, Serialize, Tabled)]
struct TopItem {
    #[tabled(rename = "#")]
    rank: usize,
    #[tabled(rename = "Item")]
    item: String,
    #[tabled(rename = "Count")]
    count: usize,
    #[tabled(rename = "% of Total")]
    percentage: String,
}

#[derive(Debug, Serialize)]
struct LogReport {
    total_entries: usize,
    allowed_count: usize,
    blocked_count: usize,
    unique_users: usize,
    unique_domains: usize,
    total_bytes: u64,
    top_users: Vec<(String, usize)>,
    top_domains: Vec<(String, usize)>,
    top_blocked: Vec<(String, usize)>,
    top_categories: Vec<(String, usize)>,
}

fn extract_domain(url_or_domain: &str) -> String {
    let s = url_or_domain.trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    s.split('/').next().unwrap_or(s).to_lowercase()
}

fn is_blocked(action: &str) -> bool {
    let a = action.to_lowercase();
    a.contains("block") || a.contains("denied") || a.contains("deny")
        || a.contains("drop") || a.contains("reject")
}

fn count_top_n(map: &HashMap<String, usize>, n: usize, total: usize) -> Vec<TopItem> {
    let mut sorted: Vec<_> = map.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    sorted.into_iter().take(n).enumerate()
        .map(|(i, (item, &count))| TopItem {
            rank: i + 1,
            item: if item.len() > 55 { format!("{}...", &item[..52]) } else { item.clone() },
            count,
            percentage: format!("{:.1}%", (count as f64 / total.max(1) as f64) * 100.0),
        })
        .collect()
}

pub fn run(input: &str, _source: &str, top: usize, blocked_only: bool, output: Option<&str>) -> Result<()> {
    println!("{} {}", "Parsing proxy logs from:".green().bold(), input.yellow());
    println!();

    let content = fs::read_to_string(input).with_context(|| format!("Failed to read: {}", input))?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());

    let mut entries: Vec<LogEntry> = Vec::new();
    for result in reader.deserialize() {
        match result {
            Ok(entry) => entries.push(entry),
            Err(e) => eprintln!("{} Skipping row: {}", "Warning:".yellow(), e),
        }
    }

    if entries.is_empty() {
        println!("{}", "No log entries found.".yellow());
        return Ok(());
    }

    let total = entries.len();
    let bar = indicatif::ProgressBar::new(total as u64);
    bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("  Analyzing [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("##-"),
    );

    let mut user_counts: HashMap<String, usize> = HashMap::new();
    let mut domain_counts: HashMap<String, usize> = HashMap::new();
    let mut blocked_domains: HashMap<String, usize> = HashMap::new();
    let mut category_counts: HashMap<String, usize> = HashMap::new();
    let mut allowed = 0usize;
    let mut blocked = 0usize;
    let mut total_bytes: u64 = 0;
    let mut unique_users: HashMap<String, bool> = HashMap::new();
    let mut unique_domains: HashMap<String, bool> = HashMap::new();

    for entry in &entries {
        let domain = entry.domain.as_deref()
            .or(entry.url.as_deref())
            .map(extract_domain)
            .unwrap_or_else(|| "unknown".to_string());
        let user = entry.user.as_deref().unwrap_or("unknown").to_string();
        let action_str = entry.action.as_deref().unwrap_or("unknown");
        let entry_blocked = is_blocked(action_str);

        if entry_blocked {
            blocked += 1;
            *blocked_domains.entry(domain.clone()).or_insert(0) += 1;
        } else {
            allowed += 1;
        }

        if !blocked_only || entry_blocked {
            *user_counts.entry(user.clone()).or_insert(0) += 1;
            *domain_counts.entry(domain.clone()).or_insert(0) += 1;
        }

        if let Some(ref cat) = entry.category {
            *category_counts.entry(cat.clone()).or_insert(0) += 1;
        }
        if let Some(b) = entry.bytes { total_bytes += b; }
        unique_users.insert(user, true);
        unique_domains.insert(domain, true);
        bar.inc(1);
    }
    bar.finish_and_clear();

    println!("  {}", "--- LOG ANALYSIS SUMMARY ---".white().bold());
    println!("  Total entries:    {}", total.to_string().cyan());
    println!("  Allowed:          {}", allowed.to_string().green());
    println!("  Blocked:          {}", blocked.to_string().red());
    println!("  Unique users:     {}", unique_users.len().to_string().cyan());
    println!("  Unique domains:   {}", unique_domains.len().to_string().cyan());
    println!("  Total data:       {:.2} MB", total_bytes as f64 / (1024.0 * 1024.0));
    println!();

    let top_users = count_top_n(&user_counts, top, total);
    if !top_users.is_empty() {
        println!("  {}", "TOP USERS BY REQUESTS".yellow().bold());
        println!("{}", Table::new(&top_users));
        println!();
    }

    let top_doms = count_top_n(&domain_counts, top, total);
    if !top_doms.is_empty() {
        println!("  {}", "TOP DOMAINS".yellow().bold());
        println!("{}", Table::new(&top_doms));
        println!();
    }

    let top_blk = count_top_n(&blocked_domains, top, blocked.max(1));
    if !top_blk.is_empty() {
        println!("  {}", "TOP BLOCKED DOMAINS".red().bold());
        println!("{}", Table::new(&top_blk));
        println!();
    }

    let top_cats = count_top_n(&category_counts, top, total);
    if !top_cats.is_empty() {
        println!("  {}", "TOP CATEGORIES".yellow().bold());
        println!("{}", Table::new(&top_cats));
    }

    if let Some(output_path) = output {
        let report = LogReport {
            total_entries: total, allowed_count: allowed, blocked_count: blocked,
            unique_users: unique_users.len(), unique_domains: unique_domains.len(),
            total_bytes,
            top_users: user_counts.into_iter().collect(),
            top_domains: domain_counts.into_iter().collect(),
            top_blocked: blocked_domains.into_iter().collect(),
            top_categories: category_counts.into_iter().collect(),
        };
        let json = serde_json::to_string_pretty(&report).context("Failed to serialize")?;
        fs::write(output_path, &json).with_context(|| format!("Failed to write: {}", output_path))?;
        println!("\n  Report exported to: {}", output_path.yellow());
    }

    Ok(())
}
