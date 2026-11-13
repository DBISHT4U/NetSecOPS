mod auditor;
mod logparser;
mod pac;
mod ssl_checker;
mod traffic;

use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(
    name = "netsecops",
    version,
    about = "⚡ Blazing-fast Network Security Operations Toolkit",
    long_about = "A CLI toolkit for network security engineers.\nAudit firewall rules, parse proxy logs, check SSL certs, test PAC files, and analyze traffic.\n\nBuilt with Rust for maximum performance.",
    after_help = "EXAMPLES:\n  netsecops audit-rules --input rules.csv --format paloalto\n  netsecops parse-logs --source zscaler --input access.log --top 20\n  netsecops ssl-check --input domains.txt --warn-days 30\n  netsecops pac-test --input proxy.pac --url https://google.com\n  netsecops traffic-analyze --input capture.csv --threshold 100"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}
