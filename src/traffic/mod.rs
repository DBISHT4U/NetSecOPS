use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tabled::{Table, Tabled};

#[derive(Debug, Deserialize)]
struct TrafficEntry {
    #[serde(alias = "Source", alias = "source", alias = "src_ip", alias = "SrcIP", alias = "SourceIP")]
    source: String,
    #[serde(alias = "Destination", alias = "destination", alias = "dst_ip", alias = "DstIP", alias = "DestIP")]
    destination: String,
    #[serde(alias = "Port", alias = "port", alias = "dst_port", alias = "DstPort", alias = "DestPort")]
    port: Option<String>,
    #[serde(alias = "Protocol", alias = "protocol", alias = "proto")]
    protocol: Option<String>,
    #[serde(alias = "Bytes", alias = "bytes", alias = "size")]
    bytes: Option<u64>,
    #[serde(alias = "Action", alias = "action", alias = "status")]
    action: Option<String>,
}

#[derive(Debug, Serialize, Tabled)]
struct SuspiciousHost {
    #[tabled(rename = "Source IP")]
    source: String,
    #[tabled(rename = "Connections")]
    connections: u64,
    #[tabled(rename = "Unique Destinations")]
    unique_dests: usize,
    #[tabled(rename = "Ports Used")]
    unique_ports: usize,
    #[tabled(rename = "Risk")]
    risk: String,
}

#[derive(Debug, Serialize, Tabled)]
struct PortStat {
    #[tabled(rename = "Port")]
    port: String,
    #[tabled(rename = "Protocol")]
    service: String,
    #[tabled(rename = "Connections")]
    count: usize,
    #[tabled(rename = "% of Total")]
    percentage: String,
}

fn get_service_name(port: &str) -> &str {
    match port {
        "21" => "FTP",
        "22" => "SSH",
        "23" => "Telnet",
        "25" => "SMTP",
        "53" => "DNS",
        "80" => "HTTP",
        "110" => "POP3",
        "135" => "MS-RPC",
        "137" | "138" | "139" => "NetBIOS",
        "143" => "IMAP",
        "443" => "HTTPS",
        "445" => "SMB",
        "993" => "IMAPS",
        "995" => "POP3S",
        "1433" => "MSSQL",
        "1434" => "MSSQL-Browser",
        "3306" => "MySQL",
        "3389" => "RDP",
        "5432" => "PostgreSQL",
        "5900" => "VNC",
        "6379" => "Redis",
        "8080" => "HTTP-Proxy",
        "8443" => "HTTPS-Alt",
        "27017" => "MongoDB",
        _ => "Other",
    }
}

fn is_suspicious_port(port: &str) -> bool {
    matches!(
        port,
        "23" | "445" | "135" | "137" | "138" | "139" | "1433" | "3389" | "4444" | "5900"
            | "6379" | "27017" | "6667" | "6668" | "6669" | "31337"
    )
}

pub fn run(input: &str, threshold: u64, output: Option<&str>) -> Result<()> {
    println!(
        "{} {}",
        "📡 Analyzing traffic from:".green().bold(),
        input.yellow()
    );
    println!(
        "  🎯 Connection threshold: {}\n",
        threshold.to_string().cyan()
    );

    let content =
        fs::read_to_string(input).with_context(|| format!("Failed to read: {}", input))?;

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());

    let mut entries: Vec<TrafficEntry> = Vec::new();
    for result in reader.deserialize() {
        match result {
            Ok(e) => entries.push(e),
            Err(e) => eprintln!("{} Skipping: {}", "⚠".yellow(), e),
        }
    }

    if entries.is_empty() {
        println!("{}", "No traffic entries found.".yellow());
        return Ok(());
    }

    let total = entries.len();
    println!("  📋 Total connections: {}", total.to_string().cyan());

    // Analyze source IPs
    let mut src_stats: HashMap<String, (u64, HashMap<String, bool>, HashMap<String, bool>)> =
        HashMap::new();
    let mut port_counts: HashMap<String, usize> = HashMap::new();
    let mut suspicious_ports_found: Vec<(String, String, String)> = Vec::new();
    let mut total_bytes: u64 = 0;

    for entry in &entries {
        let stat = src_stats
            .entry(entry.source.clone())
            .or_insert((0, HashMap::new(), HashMap::new()));
        stat.0 += 1;
        stat.1.insert(entry.destination.clone(), true);
        if let Some(ref port) = entry.port {
            stat.2.insert(port.clone(), true);
            *port_counts.entry(port.clone()).or_insert(0) += 1;

            if is_suspicious_port(port) {
                suspicious_ports_found.push((
                    entry.source.clone(),
                    entry.destination.clone(),
                    port.clone(),
                ));
            }
        }
        if let Some(b) = entry.bytes {
            total_bytes += b;
        }
    }

    // Find suspicious hosts (exceeding threshold)
    let mut suspicious_hosts: Vec<SuspiciousHost> = src_stats
        .iter()
        .filter(|(_, (count, _, _))| *count >= threshold)
        .map(|(src, (count, dests, ports))| {
            let risk = if *count > threshold * 3 && dests.len() > 20 {
                "🔴 HIGH".to_string()
            } else if *count > threshold * 2 || ports.len() > 10 {
                "🟡 MEDIUM".to_string()
            } else {
                "🟢 LOW".to_string()
            };
            SuspiciousHost {
                source: src.clone(),
                connections: *count,
                unique_dests: dests.len(),
                unique_ports: ports.len(),
                risk,
            }
        })
        .collect();

    suspicious_hosts.sort_by(|a, b| b.connections.cmp(&a.connections));

    // Port statistics
    let mut port_stats: Vec<PortStat> = port_counts
        .iter()
        .map(|(port, &count)| PortStat {
            port: port.clone(),
            service: get_service_name(port).to_string(),
            count,
            percentage: format!("{:.1}%", (count as f64 / total as f64) * 100.0),
        })
        .collect();
    port_stats.sort_by(|a, b| b.count.cmp(&a.count));

    // Print results
    println!(
        "  💾 Total data: {:.2} MB",
        total_bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  🖥️  Unique sources: {}",
        src_stats.len().to_string().cyan()
    );
    println!();

    // Port Analysis
    println!("  {}", "━━━ TOP PORTS ━━━".white().bold());
    let top_ports: Vec<&PortStat> = port_stats.iter().take(15).collect();
    if !top_ports.is_empty() {
        let table = Table::new(top_ports).to_string();
        println!("{}", table);
        println!();
    }

    // Suspicious Hosts
    if !suspicious_hosts.is_empty() {
        println!(
            "  {}",
            "━━━ HOSTS EXCEEDING THRESHOLD ━━━".yellow().bold()
        );
        let table = Table::new(&suspicious_hosts).to_string();
        println!("{}", table);
        println!();
    } else {
        println!(
            "  {} No hosts exceeded the {} connection threshold.",
            "✅".green(),
            threshold
        );
    }

    // Suspicious port usage
    if !suspicious_ports_found.is_empty() {
        println!(
            "  {} {} connections on suspicious ports detected:",
            "⚠️".red().bold(),
            suspicious_ports_found.len().to_string().red()
        );
        let show_count = suspicious_ports_found.len().min(20);
        for (src, dst, port) in suspicious_ports_found.iter().take(show_count) {
            println!(
                "    {} → {}:{} ({})",
                src.cyan(),
                dst.yellow(),
                port.red(),
                get_service_name(port)
            );
        }
        if suspicious_ports_found.len() > 20 {
            println!(
                "    ... and {} more",
                suspicious_ports_found.len() - 20
            );
        }
        println!();
    }

    // Export
    if let Some(output_path) = output {
        let report = serde_json::json!({
            "total_connections": total,
            "total_bytes": total_bytes,
            "unique_sources": src_stats.len(),
            "suspicious_hosts": suspicious_hosts,
            "suspicious_port_connections": suspicious_ports_found.len(),
            "top_ports": port_stats.iter().take(20).collect::<Vec<_>>(),
        });
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(output_path, &json)
            .with_context(|| format!("Failed to write to: {}", output_path))?;
        println!(
            "  {} Report exported to: {}",
            "📁".green(),
            output_path.yellow()
        );
    }

    Ok(())
}
