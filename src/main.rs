#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    clippy::unnecessary_sort_by,
    clippy::redundant_closure,
    clippy::type_complexity,
    clippy::regex_creation_in_loops,
    clippy::needless_range_loop,
    clippy::manual_map,
    clippy::collapsible_if,
    clippy::collapsible_else_if,
    clippy::single_match,
    clippy::too_many_arguments,
    clippy::needless_return,
)]
mod auditor;
mod logparser;
mod pac;
mod ssl_checker;
mod traffic;
// === NEW MODULES ===
mod dns_analyzer;
mod ip_reputation;
mod secrets_scanner;
mod config_diff;
mod password_audit;
mod file_integrity;

use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(
    name = "netsecops",
    version,
    about = "⚡ Blazing-fast Network Security Operations Toolkit",
    long_about = "A CLI toolkit for network security engineers.\nAudit firewall rules, parse proxy logs, check SSL certs, test PAC files, analyze traffic,\nscan for secrets, check DNS anomalies, audit passwords, diff configs, and more.\n\nBuilt with Rust for maximum performance.",
    after_help = "EXAMPLES:\n  netsecops audit-rules --input rules.csv --format paloalto\n  netsecops parse-logs --source zscaler --input access.log\n  netsecops ssl-check --input domains.txt --warn-days 30\n  netsecops pac-test --input proxy.pac --url https://google.com\n  netsecops traffic-analyze --input capture.csv --threshold 100\n  netsecops dns-analyze --input dns-logs.csv --top 15\n  netsecops ip-check --input suspicious-ips.txt --threat-feed known-bad.txt\n  netsecops scan-secrets --input ./my-project/\n  netsecops config-diff --before old-rules.csv --after new-rules.csv\n  netsecops password-audit --input passwords.txt --hibp\n  netsecops fim --input /etc --mode init --output baseline.json\n  netsecops fim --input /etc --mode check --baseline baseline.json"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ============================================================
    //  ORIGINAL MODULES
    // ============================================================

    /// 🛡️ Audit firewall rules for security risks
    AuditRules {
        /// Path to firewall rules file (CSV)
        #[arg(short, long)]
        input: String,

        /// Firewall vendor format: paloalto, fortinet, cisco, generic
        #[arg(short, long, default_value = "generic")]
        format: String,

        /// Export report to JSON file
        #[arg(short, long)]
        output: Option<String>,

        /// Minimum risk score to flag (1-10)
        #[arg(long, default_value = "3")]
        min_risk: u8,
    },

    /// 📊 Parse and analyze proxy/firewall logs
    ParseLogs {
        /// Path to log file
        #[arg(short, long)]
        input: String,

        /// Log source: zscaler, forcepoint, bluecoat, generic
        #[arg(short, long, default_value = "generic")]
        source: String,

        /// Show top N results
        #[arg(short, long, default_value = "10")]
        top: usize,

        /// Show only blocked entries
        #[arg(long)]
        blocked_only: bool,

        /// Export report to file (csv/json)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// 🔒 Check SSL certificate expiry for domains
    SslCheck {
        /// Path to file with domain list (one per line) OR single domain
        #[arg(short, long)]
        input: String,

        /// Days threshold for expiry warning
        #[arg(short, long, default_value = "30")]
        warn_days: i64,

        /// Export report to JSON file
        #[arg(short, long)]
        output: Option<String>,
    },

    /// 🌐 Test and validate PAC (Proxy Auto-Config) files
    PacTest {
        /// Path to PAC file
        #[arg(short, long)]
        input: String,

        /// URL to test against PAC file
        #[arg(short, long)]
        url: Option<String>,

        /// Validate PAC file syntax
        #[arg(long)]
        validate: bool,

        /// Test multiple URLs from file (one per line)
        #[arg(long)]
        url_list: Option<String>,
    },

    /// 📡 Analyze network traffic for anomalies
    TrafficAnalyze {
        /// Path to traffic log (CSV format)
        #[arg(short, long)]
        input: String,

        /// Connection count threshold for flagging
        #[arg(short, long, default_value = "50")]
        threshold: u64,

        /// Export report to JSON
        #[arg(short, long)]
        output: Option<String>,
    },

    // ============================================================
    //  NEW MODULES
    // ============================================================

    /// 🔍 Analyze DNS logs for DGA domains, tunneling, and anomalies
    DnsAnalyze {
        /// Path to DNS log file (CSV)
        #[arg(short, long)]
        input: String,

        /// Show top N results
        #[arg(short, long, default_value = "10")]
        top: usize,

        /// Export report to JSON
        #[arg(short, long)]
        output: Option<String>,
    },

    /// 🔎 Check IPs against threat intelligence feeds
    IpCheck {
        /// Path to file with IPs (one per line)
        #[arg(short, long)]
        input: String,

        /// Optional threat feed file (one IP per line)
        #[arg(long)]
        threat_feed: Option<String>,

        /// Export report to JSON
        #[arg(short, long)]
        output: Option<String>,
    },

    /// 🔐 Scan files/directories for leaked secrets and API keys
    ScanSecrets {
        /// Path to file or directory to scan
        #[arg(short, long)]
        input: String,

        /// Max file size to scan in KB (skip larger files)
        #[arg(long, default_value = "512")]
        max_size: u64,

        /// Export report to JSON
        #[arg(short, long)]
        output: Option<String>,
    },

    /// 🔄 Compare two config files and flag security regressions
    ConfigDiff {
        /// Path to original (before) config
        #[arg(long)]
        before: String,

        /// Path to new (after) config
        #[arg(long)]
        after: String,

        /// Export report to JSON
        #[arg(short, long)]
        output: Option<String>,

        /// Number of context lines around changes
        #[arg(long, default_value = "0")]
        context: usize,
    },

    /// 🔑 Audit password strength and check against known breaches
    PasswordAudit {
        /// Path to file with passwords (one per line)
        #[arg(short, long)]
        input: String,

        /// Generate SHA1 hashes for HIBP k-anonymity API
        #[arg(long)]
        hibp: bool,

        /// Export report to JSON
        #[arg(short, long)]
        output: Option<String>,
    },

    /// 🛡️ File Integrity Monitor — baseline and verify file hashes
    Fim {
        /// Path to directory or file list to monitor
        #[arg(short, long)]
        input: String,

        /// Mode: 'init' (create baseline) or 'check' (verify against baseline)
        #[arg(short, long, default_value = "check")]
        mode: String,

        /// Path to baseline JSON file (for check mode)
        #[arg(long)]
        baseline: Option<String>,

        /// Export report / save baseline to this path
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn print_banner() {
    println!(
        "{}",
        r#"
  _   _      _   ____            ___
 | \ | | ___| |_/ ___|  ___  ___|  _ \ _ __  ___
 |  \| |/ _ \ __\___ \ / _ \/ __| | | | '_ \/ __|
 | |\  |  __/ |_ ___) |  __/ (__| |_| | |_) \__ \
 |_| \_|\___|\__|____/ \___|\___|____/| .__/|___/
                                      |_|
"#
        .cyan()
        .bold()
    );
    println!(
        "  {}\n",
        "⚡ Blazing-fast Network Security Operations Toolkit"
            .white()
            .bold()
    );
}

fn main() {
    print_banner();

    let cli = Cli::parse();

    let result = match cli.command {
        // --- Original modules ---
        Commands::AuditRules {
            input,
            format,
            output,
            min_risk,
        } => auditor::run(&input, &format, output.as_deref(), min_risk),

        Commands::ParseLogs {
            input,
            source,
            top,
            blocked_only,
            output,
        } => logparser::run(&input, &source, top, blocked_only, output.as_deref()),

        Commands::SslCheck {
            input,
            warn_days,
            output,
        } => ssl_checker::run(&input, warn_days, output.as_deref()),

        Commands::PacTest {
            input,
            url,
            validate,
            url_list,
        } => pac::run(&input, url.as_deref(), validate, url_list.as_deref()),

        Commands::TrafficAnalyze {
            input,
            threshold,
            output,
        } => traffic::run(&input, threshold, output.as_deref()),

        // --- New modules ---
        Commands::DnsAnalyze {
            input,
            top,
            output,
        } => dns_analyzer::run(&input, output.as_deref(), top),

        Commands::IpCheck {
            input,
            threat_feed,
            output,
        } => ip_reputation::run(&input, threat_feed.as_deref(), output.as_deref()),

        Commands::ScanSecrets {
            input,
            max_size,
            output,
        } => secrets_scanner::run(&input, output.as_deref(), max_size),

        Commands::ConfigDiff {
            before,
            after,
            output,
            context,
        } => config_diff::run(&before, &after, output.as_deref(), context),

        Commands::PasswordAudit {
            input,
            hibp,
            output,
        } => password_audit::run(&input, output.as_deref(), hibp),

        Commands::Fim {
            input,
            mode,
            baseline,
            output,
        } => file_integrity::run(&input, baseline.as_deref(), output.as_deref(), &mode),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}
