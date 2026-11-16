# ⚡ NetSecOps

**Blazing-fast CLI toolkit for Network Security Operations**

[![CI](https://github.com/DBISHT4U/NetSecOPS/actions/workflows/ci.yml/badge.svg)](https://github.com/DBISHT4U/NetSecOPS/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

*Audit firewall rules · Parse proxy logs · Check SSL certs · Test PAC files · Analyze traffic · Detect DGA domains · Check IP reputation · Scan for secrets · Diff configs · Audit passwords · Monitor file integrity*

[Installation](#installation) · [Usage](#usage) · [Examples](#examples) · [Contributing](#contributing)

---

## Why NetSecOps?

If you work with **firewalls, web proxies, or cloud security tools** (Zscaler, Forcepoint, Netskope, Palo Alto, Fortinet), you know the pain:

- 🔥 **5000+ firewall rules** and no quick way to find the risky ones
- 📊 **GB-sized proxy logs** that take forever to grep through
- 🔒 **SSL certificates** expiring silently causing outages
- 🌐 **PAC files** that are impossible to debug
- 📡 **Suspicious traffic** hiding in plain sight
- 🧬 **DGA domains** and DNS tunneling going undetected
- 🔐 **Leaked API keys** in your codebase
- 🔑 **Weak passwords** across the organization

**NetSecOps** is a single binary that handles all of this — no Python, no pip, no dependencies. Download, run, done.

## Features

| Module | Command | What It Does |
|--------|---------|-------------|
| 🛡️ **Firewall Auditor** | `audit-rules` | Scans rules for any-any, open risky ports, missing logs, shadow rules. Gives risk scores. |
| 📊 **Log Parser** | `parse-logs` | Parses Zscaler/Forcepoint/BlueCoat proxy logs. Top users, blocked domains, categories. |
| 🔒 **SSL Checker** | `ssl-check` | Bulk checks SSL certificate expiry. Warns before outages happen. |
| 🌐 **PAC Tester** | `pac-test` | Validates PAC file syntax and tests URLs against proxy rules. |
| 📡 **Traffic Analyzer** | `traffic-analyze` | Finds suspicious hosts, port scans, anomalous connections in traffic data. |
| 🔍 **DNS Analyzer** | `dns-analyze` | Detects DGA domains, DNS tunneling, data exfiltration via DNS. |
| 🔎 **IP Reputation** | `ip-check` | Checks IPs against threat feeds, detects bogons and suspicious patterns. |
| 🔐 **Secrets Scanner** | `scan-secrets` | Finds leaked API keys, tokens, passwords, private keys in files. |
| 🔄 **Config Diff** | `config-diff` | Compares firewall configs, flags security regressions (deny→allow, etc). |
| 🔑 **Password Auditor** | `password-audit` | Checks strength, catches common passwords, generates HIBP hashes. |
| 🛡️ **File Integrity** | `fim` | Creates hash baselines of critical files and detects tampering. |

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
cd NetSecOPS
cargo build --release
# Binary will be at target/release/netsecops
```

## Usage

### 🛡️ Firewall Rule Auditor

```bash
netsecops audit-rules --input rules.csv
netsecops audit-rules --input rules.csv --format paloalto --output report.json
netsecops audit-rules --input rules.csv --min-risk 7
```

### 📊 Proxy Log Parser

```bash
netsecops parse-logs --input access.log --source zscaler
netsecops parse-logs --input access.log --source forcepoint --top 20 --blocked-only
```

### 🔒 SSL Certificate Checker

```bash
netsecops ssl-check --input google.com
netsecops ssl-check --input domains.txt --warn-days 30 --output ssl-report.json
```

### 🌐 PAC File Tester

```bash
netsecops pac-test --input proxy.pac --validate
netsecops pac-test --input proxy.pac --url https://mail.google.com
```

### 📡 Traffic Analyzer

```bash
netsecops traffic-analyze --input traffic.csv --threshold 100
```

### 🔍 DNS Analyzer *(NEW)*

Analyze DNS query logs for DGA (Domain Generation Algorithm) domains, DNS tunneling attempts, and data exfiltration.

```bash
# Basic DNS analysis
netsecops dns-analyze --input dns-logs.csv

# Show top 20 results and export
netsecops dns-analyze --input dns-logs.csv --top 20 --output dns-report.json
```

**What it detects:**
- 🧬 DGA domains (high entropy, unusual character distribution)
- 🕳️ DNS tunneling (long subdomains, excessive TXT queries, many unique subdomains per domain)
- 📈 Top queried domains with client counts

### 🔎 IP Reputation Checker *(NEW)*

Check IPs against threat intelligence feeds and built-in heuristics.

```bash
# Check IPs with built-in rules
netsecops ip-check --input suspicious-ips.txt

# Check against a threat feed
netsecops ip-check --input ips.txt --threat-feed known-bad-ips.txt --output ip-report.json
```

**What it detects:**
- 🔴 IPs matching threat intelligence feeds
- 🟡 Bogon/RFC1918 addresses in external traffic
- 🟡 Suspicious IP patterns (sequential octets, repeated octets)

### 🔐 Secrets Scanner *(NEW)*

Scan files and directories for leaked API keys, tokens, passwords, and credentials.

```bash
# Scan a project directory
netsecops scan-secrets --input ./my-project/

# Scan with custom max file size (in KB)
netsecops scan-secrets --input ./src/ --max-size 1024 --output secrets-report.json
```

**What it finds:**
- AWS Access Keys & Secret Keys
- GitHub / Slack / Google / Stripe / SendGrid tokens
- Private keys (RSA, EC, DSA)
- Database connection strings
- Hardcoded passwords and Bearer tokens
- JWT tokens and Basic Auth credentials

### 🔄 Config Diff *(NEW)*

Compare two firewall/security configuration files and flag security regressions.

```bash
# Compare before and after configs
netsecops config-diff --before old-rules.csv --after new-rules.csv

# Export to JSON
netsecops config-diff --before old.csv --after new.csv --output diff-report.json
```

**What it flags:**
- 🔴 **CRITICAL:** deny→allow changes, source opened to ANY, new allow-any rules
- 🟠 **HIGH:** logging removed, risky ports opened, deny rules removed
- 🟢 **IMPROVED:** allow→deny changes, ANY restrictions added

### 🔑 Password Auditor *(NEW)*

Audit password strength offline and generate hashes for HIBP (Have I Been Pwned) checking.

```bash
# Basic strength audit
netsecops password-audit --input passwords.txt

# With HIBP hash generation
netsecops password-audit --input passwords.txt --hibp --output audit-report.json
```

**What it checks:**
- Length, complexity, character variety
- Common password matching (top 100 list)
- Sequential characters and keyboard patterns
- SHA1 hash generation for HIBP k-anonymity API

### 🛡️ File Integrity Monitor *(NEW)*

Create SHA-256 hash baselines of critical files and detect unauthorized changes.

```bash
# Step 1: Create baseline
netsecops fim --input /etc/nginx/ --mode init --output baseline.json

# Step 2: Check for changes later
netsecops fim --input /etc/nginx/ --mode check --baseline baseline.json

# Monitor specific files from a list
netsecops fim --input critical-files.txt --mode init --output baseline.json
```

**What it detects:**
- 🔴 Modified files (hash changed)
- 🟡 Removed files
- 🔵 New files not in baseline
- 🟠 Size changes

## Examples

The `examples/` directory contains sample data files to try all modules:

```bash
# Original modules
netsecops audit-rules --input examples/sample-firewall-rules.csv
netsecops parse-logs --input examples/sample-proxy-logs.csv
netsecops pac-test --input examples/sample.pac --validate
netsecops traffic-analyze --input examples/sample-traffic.csv --threshold 3

# New modules
netsecops dns-analyze --input examples/sample-dns-logs.csv
netsecops ip-check --input examples/sample-ips.txt --threat-feed examples/sample-threat-feed.txt
netsecops scan-secrets --input examples/
netsecops config-diff --before examples/sample-config-before.csv --after examples/sample-config-after.csv
netsecops password-audit --input examples/sample-passwords.txt --hibp
netsecops fim --input examples/ --mode init --output /tmp/baseline.json
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

- [ ] Zscaler ZIA API integration
- [ ] Netskope log support
- [ ] PCAP file analysis (native)
- [ ] Check Point firewall support
- [ ] HTML report generation
- [ ] Config file for default settings
- [ ] Syslog/CEF input format
- [ ] Integration with SIEM (Splunk, QRadar export)
- [ ] HIBP online API integration for password audit
- [ ] CVE feed aggregator module

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT — see [LICENSE](LICENSE).

---

**Built with 🦀 Rust for the Network Security community**

*If this tool helped you, give it a ⭐ on GitHub!*
