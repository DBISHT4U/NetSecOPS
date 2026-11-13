use anyhow::{Context, Result};
use colored::*;
use serde::Serialize;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use tabled::{Table, Tabled};

#[derive(Debug, Serialize, Tabled, Clone)]
pub struct CertResult {
    #[tabled(rename = "Domain")]
    pub domain: String,
    #[tabled(rename = "Status")]
    pub status: String,
    #[tabled(rename = "Issuer")]
    pub issuer: String,
    #[tabled(rename = "Expires")]
    pub expires: String,
    #[tabled(rename = "Days Left")]
    pub days_left: String,
}

fn check_cert(domain: &str, warn_days: i64) -> CertResult {
    let addr = format!("{}:443", domain.trim());

    let tcp = match TcpStream::connect(&addr) {
        Ok(stream) => {
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .ok();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                .ok();
            stream
        }
        Err(e) => {
            return CertResult {
                domain: domain.to_string(),
                status: "⛔ CONNECT FAILED".to_string(),
                issuer: "-".to_string(),
                expires: "-".to_string(),
                days_left: format!("Error: {}", e),
            };
        }
    };

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = match rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .try_into() as std::result::Result<rustls::ClientConfig, _>
    {
        Ok(c) => c,
        Err(_) => {
            // Fallback: just build it normally (the above is already correct for rustls 0.22)
            let mut root_store2 = rustls::RootCertStore::empty();
            root_store2.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store2)
                .with_no_client_auth()
        }
    };

    let server_name = match rustls::pki_types::ServerName::try_from(domain.trim().to_string()) {
        Ok(sn) => sn,
        Err(_) => {
            return CertResult {
                domain: domain.to_string(),
                status: "⛔ INVALID DOMAIN".to_string(),
                issuer: "-".to_string(),
                expires: "-".to_string(),
                days_left: "Invalid domain name".to_string(),
            };
        }
    };

    let mut conn = match rustls::ClientConnection::new(Arc::new(config), server_name) {
        Ok(c) => c,
        Err(e) => {
            return CertResult {
                domain: domain.to_string(),
                status: "⛔ TLS ERROR".to_string(),
                issuer: "-".to_string(),
                expires: "-".to_string(),
                days_left: format!("{}", e),
            };
        }
    };

    let mut stream = rustls::Stream::new(&mut conn, &mut &tcp);

    // Perform the handshake
    let _ = stream.write_all(b"");
    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf);

    let certs = conn.peer_certificates();
    match certs {
        Some(chain) if !chain.is_empty() => {
            let cert_der = &chain[0];
            match x509_parser::parse_x509_certificate(cert_der.as_ref()) {
                Ok((_, cert)) => {
                    let not_after = cert.validity().not_after.to_datetime();
                    let issuer = cert
                        .issuer()
                        .iter_organization()
                        .next()
                        .and_then(|o| o.as_str().ok())
                        .unwrap_or("Unknown")
                        .to_string();

                    let expires_str = not_after.to_string();
                    let now = chrono::Utc::now();
                    let expires_chrono = chrono::NaiveDateTime::parse_from_str(
                        &expires_str[..19],
                        "%Y-%m-%dT%H:%M:%S",
                    )
                    .unwrap_or_default();
                    let expires_dt = expires_chrono.and_utc();
                    let days = (expires_dt - now).num_days();

                    let status = if days < 0 {
                        "🔴 EXPIRED".to_string()
                    } else if days <= warn_days {
                        "🟡 EXPIRING SOON".to_string()
                    } else {
                        "🟢 VALID".to_string()
                    };

                    let issuer_short = if issuer.len() > 30 {
                        format!("{}...", &issuer[..27])
                    } else {
                        issuer
                    };

                    CertResult {
                        domain: domain.to_string(),
                        status,
                        issuer: issuer_short,
                        expires: expires_str[..10].to_string(),
                        days_left: format!("{} days", days),
                    }
                }
                Err(e) => CertResult {
                    domain: domain.to_string(),
                    status: "⛔ PARSE ERROR".to_string(),
                    issuer: "-".to_string(),
                    expires: "-".to_string(),
                    days_left: format!("{}", e),
                },
            }
        }
        _ => CertResult {
            domain: domain.to_string(),
            status: "⛔ NO CERT".to_string(),
            issuer: "-".to_string(),
            expires: "-".to_string(),
            days_left: "No certificate presented".to_string(),
        },
    }
}

pub fn run(input: &str, warn_days: i64, output: Option<&str>) -> Result<()> {
    println!(
        "{} {}",
        "🔒 Checking SSL certificates:".green().bold(),
        input.yellow()
    );
    println!(
        "  ⏰ Warning threshold: {} days\n",
        warn_days.to_string().cyan()
    );

    // Input can be a file (one domain per line) or a single domain
    let domains: Vec<String> = if std::path::Path::new(input).exists() {
        fs::read_to_string(input)
            .with_context(|| format!("Failed to read: {}", input))?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    } else {
        vec![input.to_string()]
    };

    if domains.is_empty() {
        println!("{}", "No domains to check.".yellow());
        return Ok(());
    }

    let bar = indicatif::ProgressBar::new(domains.len() as u64);
    bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("  Checking [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let mut results: Vec<CertResult> = Vec::new();
    for domain in &domains {
        bar.set_message(domain.clone());
        let result = check_cert(domain, warn_days);
        results.push(result);
        bar.inc(1);
    }
    bar.finish_and_clear();

    // Summary
    let valid = results.iter().filter(|r| r.status.contains("VALID")).count();
    let expiring = results
        .iter()
        .filter(|r| r.status.contains("EXPIRING"))
        .count();
    let expired = results
        .iter()
        .filter(|r| r.status.contains("EXPIRED"))
        .count();
    let errors = results.len() - valid - expiring - expired;

    println!("  {}", "━━━ SSL CHECK SUMMARY ━━━".white().bold());
    println!(
        "  🟢 Valid:         {}",
        valid.to_string().green().bold()
    );
    println!(
        "  🟡 Expiring Soon: {}",
        expiring.to_string().yellow().bold()
    );
    println!(
        "  🔴 Expired:       {}",
        expired.to_string().red().bold()
    );
    println!("  ⛔ Errors:        {}", errors.to_string().red());
    println!();

    let table = Table::new(&results).to_string();
    println!("{}", table);

    // Export
    if let Some(output_path) = output {
        let json =
            serde_json::to_string_pretty(&results).context("Failed to serialize SSL results")?;
        fs::write(output_path, &json)
            .with_context(|| format!("Failed to write to: {}", output_path))?;
        println!(
            "\n  {} Report exported to: {}",
            "📁".green(),
            output_path.yellow()
        );
    }

    Ok(())
}
