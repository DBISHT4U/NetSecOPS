<div align="center">

# ⚡ NetSecOps

**Blazing-fast CLI toolkit for Network Security Operations**

[![CI](https://github.com/DBISHT4U/NetSecOPS/actions/workflows/ci.yml/badge.svg)](https://github.com/DBISHT4U/NetSecOPS/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

*Audit firewall rules · Parse proxy logs · Check SSL certs · Test PAC files · Analyze traffic*

[Installation](#installation) · [Usage](#usage) · [Examples](#examples) · [Contributing](#contributing)

</div>

---

## Why NetSecOps?

If you work with **firewalls, web proxies, or cloud security tools** (Zscaler, Forcepoint, Netskope, Palo Alto, Fortinet), you know the pain:

- 🔥 **5000+ firewall rules** and no quick way to find the risky ones
- 📊 **GB-sized proxy logs** that take forever to grep through
- 🔒 **SSL certificates** expiring silently causing outages
- 🌐 **PAC files** that are impossible to debug
- 📡 **Suspicious traffic** hiding in plain sight

**NetSecOps** is a single binary that handles all of this — no Python, no pip, no dependencies. Download, run, done.

## Features

| Module | What It Does |
|--------|-------------|
| 🛡️ **Firewall Auditor** | Scans rules for any-any, open risky ports, missing logs, shadow rules. Gives risk scores. |
| 📊 **Log Parser** | Parses Zscaler/Forcepoint/BlueCoat proxy logs. Top users, blocked domains, categories. |
| 🔒 **SSL Checker** | Bulk checks SSL certificate expiry. Warns before outages happen. |
| 🌐 **PAC Tester** | Validates PAC file syntax and tests URLs against proxy rules. |
| 📡 **Traffic Analyzer** | Finds suspicious hosts, port scans, anomalous connections in traffic data. |

## Installation

### Download Binary (Recommended)

Download the latest release for your platform from [Releases](https://github.com/DBISHT4U/NetSecOPS/releases):

```bash
# Linux
curl -L https://github.com/DBISHT4U/NetSecOPS/releases/latest/download/netsecops-x86_64-unknown-linux-gnu -o netsecops
chmod +x netsecops
sudo mv netsecops /usr/local/bin/

# macOS
curl -L https://github.com/DBISHT4U/NetSecOPS/releases/latest/download/netsecops-x86_64-apple-darwin -o netsecops
chmod +x netsecops
sudo mv netsecops /usr/local/bin/
```

### Build from Source

```bash
git clone https://github.com/DBISHT4U/NetSecOPS.git
cd netsecops
cargo build --release
# Binary will be at target/release/netsecops
```

## Usage

### 🛡️ Firewall Rule Auditor

Audit your firewall rules for security risks. Supports CSV exports from Palo Alto, Fortinet, Cisco ASA, or any generic CSV.

```bash
# Basic audit
netsecops audit-rules --input rules.csv

# Specify vendor format and export report
netsecops audit-rules --input rules.csv --format paloalto --output report.json

# Only show critical/high findings (risk score >= 7)
netsecops audit-rules --input rules.csv --min-risk 7
```

**What it detects:**
- ❌ Any-Any-Any allow rules (risk: 10/10)
- ❌ Source ANY with allow (risk: 8/10)
- ❌ Risky ports open from ANY (RDP, SSH, SMB, Telnet, DB ports)
- ❌ Service ANY (all ports open)
- ⚠️ Logging disabled
- ⚠️ Disabled rules still in ruleset

**Expected CSV format:**
```csv
Rule Name,Source,Destination,Service,Action,Enabled,Log
Allow-Web,10.0.1.0/24,192.168.1.100,443,allow,yes,yes
```

### 📊 Proxy Log Parser

Parse and analyze proxy logs from Zscaler, Forcepoint, BlueCoat, or any CSV-based log.

```bash
# Basic analysis
netsecops parse-logs --input access.log --source zscaler

# Show top 20 results, blocked only
netsecops parse-logs --input access.log --source forcepoint --top 20 --blocked-only

# Export to JSON
netsecops parse-logs --input access.log --output report.json
```

**What it shows:**
- 👤 Top users by request count
- 🌐 Top accessed domains
- 🚫 Top blocked domains
- 📂 Top URL categories
- 💾 Bandwidth usage

### 🔒 SSL Certificate Checker

Check SSL certificate expiry for one domain or hundreds.

```bash
# Check single domain
netsecops ssl-check --input google.com

# Bulk check from file
netsecops ssl-check --input domains.txt --warn-days 30

# Export results
netsecops ssl-check --input domains.txt --output ssl-report.json
```

### 🌐 PAC File Tester

Validate and test Proxy Auto-Config (PAC) files.

```bash
# Validate PAC syntax
netsecops pac-test --input proxy.pac --validate

# Test specific URL
netsecops pac-test --input proxy.pac --url https://mail.google.com

# Test multiple URLs
netsecops pac-test --input proxy.pac --url-list urls.txt
```

**What it checks:**
- FindProxyForURL function presence and signature
- Invalid browser APIs (alert, document, window)
- PROXY directive format
- Hardcoded IPs in proxy strings
- Missing semicolons and syntax issues

### 📡 Traffic Analyzer

Analyze network traffic for suspicious patterns.

```bash
# Basic analysis
netsecops traffic-analyze --input traffic.csv

# Custom threshold (flag hosts with 100+ connections)
netsecops traffic-analyze --input traffic.csv --threshold 100

# Export report
netsecops traffic-analyze --input traffic.csv --output traffic-report.json
```

**What it detects:**
- 🔴 Hosts with excessive connections (possible scanning)
- 🔴 Suspicious port usage (Telnet, SMB, RDP from unusual sources)
- 📊 Port distribution analysis
- 💾 Data transfer anomalies

## Examples

The `examples/` directory contains sample data files to try:

```bash
# Try firewall audit with sample data
netsecops audit-rules --input examples/sample-firewall-rules.csv

# Try log parsing
netsecops parse-logs --input examples/sample-proxy-logs.csv

# Try PAC validation
netsecops pac-test --input examples/sample.pac --validate

# Try traffic analysis
netsecops traffic-analyze --input examples/sample-traffic.csv --threshold 3
```

## Supported Vendors

| Vendor | Firewall Audit | Log Parsing | Notes |
|--------|:-:|:-:|-------|
| **Palo Alto** | ✅ | ✅ | CSV export from Panorama/firewall |
| **Fortinet** | ✅ | ✅ | FortiGate CSV logs |
| **Cisco ASA** | ✅ | 🔜 | ACL export |
| **Zscaler ZIA** | — | ✅ | NSS feed logs |
| **Forcepoint** | — | ✅ | Web Security logs |
| **BlueCoat/Symantec** | — | ✅ | ProxySG access logs |
| **Generic CSV** | ✅ | ✅ | Any CSV with matching headers |

## Roadmap

- [ ] Zscaler ZIA API integration (URL lookup, policy management)
- [ ] Netskope log support
- [ ] PCAP file analysis (native)
- [ ] Check Point firewall support
- [ ] HTML report generation
- [ ] Config file for default settings
- [ ] Syslog/CEF input format
- [ ] Integration with SIEM (Splunk, QRadar export)

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

The easiest way to contribute is **adding support for a new vendor** — we have a wishlist in the contributing guide.

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

**Built with 🦀 Rust for the Network Security community**

*If this tool helped you, give it a ⭐ on GitHub!*

</div>
