<div align="center">

```
    ╔╗╔┌─┐┌┬┐╔═╗┌─┐┌─┐╔═╗┌─┐┌─┐
    ║║║├┤  │ ╚═╗├┤ │  ║ ║├─┘└─┐
    ╝╚╝└─┘ ┴ ╚═╝└─┘└─┘╚═╝┴  └─┘
```

<h3>⚡ Blazing-fast CLI Toolkit for Network Security Operations</h3>

<p>
  <strong>One binary. Zero dependencies. Eleven powerful modules.</strong><br>
  Built with Rust for the engineers who defend networks.
</p>

<p>
  <a href="https://github.com/DBISHT4U/NetSecOPS/actions"><img src="https://github.com/DBISHT4U/NetSecOPS/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.75%2B-orange.svg?logo=rust" alt="Rust"></a>
  <a href="https://github.com/DBISHT4U/NetSecOPS/releases"><img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Platform"></a>
  <a href="https://github.com/DBISHT4U/NetSecOPS/releases"><img src="https://img.shields.io/github/v/release/DBISHT4U/NetSecOPS?label=Release&color=green" alt="Release"></a>
  <a href="https://github.com/DBISHT4U/NetSecOPS"><img src="https://img.shields.io/github/repo-size/DBISHT4U/NetSecOPS?color=purple" alt="Repo Size"></a>
</p>

<p>
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-modules">Modules</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-examples">Examples</a> •
  <a href="#-supported-vendors">Vendors</a> •
  <a href="#-contributing">Contributing</a>
</p>

<br>

<img src="https://img.shields.io/badge/-%F0%9F%9B%A1%EF%B8%8F%20Firewall%20Auditor-E74C3C?style=for-the-badge" alt="">
<img src="https://img.shields.io/badge/-%F0%9F%93%8A%20Log%20Parser-3498DB?style=for-the-badge" alt="">
<img src="https://img.shields.io/badge/-%F0%9F%94%92%20SSL%20Checker-2ECC71?style=for-the-badge" alt="">
<img src="https://img.shields.io/badge/-%F0%9F%8C%90%20PAC%20Tester-9B59B6?style=for-the-badge" alt="">
<img src="https://img.shields.io/badge/-%F0%9F%93%A1%20Traffic%20Analyzer-F39C12?style=for-the-badge" alt="">
<br>
<img src="https://img.shields.io/badge/-%F0%9F%94%8D%20DNS%20Analyzer-1ABC9C?style=for-the-badge" alt="">
<img src="https://img.shields.io/badge/-%F0%9F%94%8E%20IP%20Reputation-E67E22?style=for-the-badge" alt="">
<img src="https://img.shields.io/badge/-%F0%9F%94%90%20Secrets%20Scanner-C0392B?style=for-the-badge" alt="">
<img src="https://img.shields.io/badge/-%F0%9F%94%84%20Config%20Diff-8E44AD?style=for-the-badge" alt="">
<img src="https://img.shields.io/badge/-%F0%9F%94%91%20Password%20Audit-2980B9?style=for-the-badge" alt="">
<img src="https://img.shields.io/badge/-%F0%9F%9B%A1%EF%B8%8F%20File%20Integrity-27AE60?style=for-the-badge" alt="">

</div>

---

## 🤔 The Problem

If you work with **firewalls, web proxies, or cloud security tools** (Zscaler, Forcepoint, Netskope, Palo Alto, Fortinet), you know the pain:

| Pain Point | What Happens | NetSecOps Fix |
|:--|:--|:--|
| 🔥 **5000+ firewall rules** | No quick way to find risky ones | `audit-rules` — instant risk scoring |
| 📊 **GB-sized proxy logs** | Takes forever to grep through | `parse-logs` — blazing-fast parsing |
| 🔒 **SSL certificates** | Expire silently, cause outages | `ssl-check` — bulk expiry alerts |
| 🌐 **PAC files** | Impossible to debug | `pac-test` — validate & test URLs |
| 📡 **Suspicious traffic** | Hiding in plain sight | `traffic-analyze` — anomaly detection |
| 🧬 **DGA domains** | DNS tunneling goes undetected | `dns-analyze` — entropy-based detection |
| 🔓 **Leaked secrets** | API keys in your codebase | `scan-secrets` — 20+ pattern types |
| 🔑 **Weak passwords** | Compromised across the org | `password-audit` — strength + HIBP |
| 📝 **Config changes** | Security regressions slip through | `config-diff` — regression alerts |
| 📂 **File tampering** | Unauthorized modifications | `fim` — hash-based integrity checks |

> **NetSecOps** is a single binary that handles all of this — **no Python, no pip, no dependencies.** Download, run, done.

---

## 🚀 Quick Start

```bash
# Clone & build
git clone https://github.com/DBISHT4U/NetSecOPS.git
cd NetSecOPS && cargo build --release

# Run any module instantly
./target/release/netsecops audit-rules --input rules.csv
./target/release/netsecops dns-analyze --input dns-logs.csv
./target/release/netsecops scan-secrets --input ./my-project/
```

---

## 🧰 Modules

<table>
<tr>
<th>Module</th>
<th>Command</th>
<th>What It Does</th>
<th>Key Features</th>
</tr>
<tr>
<td>🛡️ <b>Firewall Auditor</b></td>
<td><code>audit-rules</code></td>
<td>Scans firewall rules for security risks</td>
<td>Any-any detection, risk scoring (1-10), risky port flagging, shadow rules</td>
</tr>
<tr>
<td>📊 <b>Log Parser</b></td>
<td><code>parse-logs</code></td>
<td>Parses proxy/firewall logs</td>
<td>Zscaler, Forcepoint, BlueCoat support, top users/domains/categories</td>
</tr>
<tr>
<td>🔒 <b>SSL Checker</b></td>
<td><code>ssl-check</code></td>
<td>Bulk SSL certificate expiry check</td>
<td>Custom warning thresholds, JSON export, single or bulk mode</td>
</tr>
<tr>
<td>🌐 <b>PAC Tester</b></td>
<td><code>pac-test</code></td>
<td>Validates & tests PAC files</td>
<td>Syntax validation, URL testing, bulk URL list support</td>
</tr>
<tr>
<td>📡 <b>Traffic Analyzer</b></td>
<td><code>traffic-analyze</code></td>
<td>Detects suspicious network patterns</td>
<td>Port scan detection, anomalous connections, bandwidth analysis</td>
</tr>
<tr>
<td>🔍 <b>DNS Analyzer</b></td>
<td><code>dns-analyze</code></td>
<td>Detects DGA domains & DNS tunneling</td>
<td>Shannon entropy scoring, subdomain analysis, TXT query monitoring</td>
</tr>
<tr>
<td>🔎 <b>IP Reputation</b></td>
<td><code>ip-check</code></td>
<td>Checks IPs against threat feeds</td>
<td>Custom threat feeds, bogon detection, pattern analysis</td>
</tr>
<tr>
<td>🔐 <b>Secrets Scanner</b></td>
<td><code>scan-secrets</code></td>
<td>Finds leaked credentials in files</td>
<td>20+ patterns (AWS, GitHub, Slack, Stripe, etc.), recursive scanning</td>
</tr>
<tr>
<td>🔄 <b>Config Diff</b></td>
<td><code>config-diff</code></td>
<td>Compares configs for regressions</td>
<td>deny→allow detection, ANY-open alerts, risk classification</td>
</tr>
<tr>
<td>🔑 <b>Password Auditor</b></td>
<td><code>password-audit</code></td>
<td>Audits password strength</td>
<td>Common password matching, HIBP SHA1 hashes, complexity scoring</td>
</tr>
<tr>
<td>🛡️ <b>File Integrity</b></td>
<td><code>fim</code></td>
<td>Monitors file integrity (FIM)</td>
<td>SHA-256 baselines, tamper detection, new/modified/removed tracking</td>
</tr>
</table>

---

## 📦 Installation

### Download Binary (Recommended)

Download the latest release for your platform from [**Releases**](https://github.com/DBISHT4U/NetSecOPS/releases):

```bash
# Linux (x86_64)
curl -L https://github.com/DBISHT4U/NetSecOPS/releases/latest/download/netsecops-x86_64-unknown-linux-gnu -o netsecops
chmod +x netsecops
sudo mv netsecops /usr/local/bin/

# macOS (Intel/Apple Silicon)
curl -L https://github.com/DBISHT4U/NetSecOPS/releases/latest/download/netsecops-x86_64-apple-darwin -o netsecops
chmod +x netsecops
sudo mv netsecops /usr/local/bin/
```

### Build from Source

```bash
git clone https://github.com/DBISHT4U/NetSecOPS.git
cd NetSecOPS
cargo build --release
# Binary → target/release/netsecops
```

---

## 📖 Usage

<details>
<summary><b>🛡️ Firewall Rule Auditor</b> — Audit your firewall rules for security risks</summary>

```bash
# Basic audit
netsecops audit-rules --input rules.csv

# Specify vendor format and export report
netsecops audit-rules --input rules.csv --format paloalto --output report.json

# Only show critical/high findings (risk score >= 7)
netsecops audit-rules --input rules.csv --min-risk 7
```

**Detects:** Any-Any-Any allow rules (10/10) · Source ANY with allow (8/10) · Risky ports open from ANY · Service ANY · Logging disabled · Disabled rules still in ruleset

**CSV Format:**
```csv
Rule Name,Source,Destination,Service,Action,Enabled,Log
Allow-Web,10.0.1.0/24,192.168.1.100,443,allow,yes,yes
```
</details>

<details>
<summary><b>📊 Proxy Log Parser</b> — Parse Zscaler/Forcepoint/BlueCoat logs</summary>

```bash
netsecops parse-logs --input access.log --source zscaler
netsecops parse-logs --input access.log --source forcepoint --top 20 --blocked-only
netsecops parse-logs --input access.log --output report.json
```

**Shows:** Top users by request count · Top accessed domains · Top blocked domains · URL categories · Bandwidth usage
</details>

<details>
<summary><b>🔒 SSL Certificate Checker</b> — Bulk check certificate expiry</summary>

```bash
netsecops ssl-check --input google.com
netsecops ssl-check --input domains.txt --warn-days 30 --output ssl-report.json
```
</details>

<details>
<summary><b>🌐 PAC File Tester</b> — Validate & test PAC files</summary>

```bash
netsecops pac-test --input proxy.pac --validate
netsecops pac-test --input proxy.pac --url https://mail.google.com
netsecops pac-test --input proxy.pac --url-list urls.txt
```

**Checks:** FindProxyForURL presence · Invalid browser APIs · PROXY directive format · Hardcoded IPs · Syntax issues
</details>

<details>
<summary><b>📡 Traffic Analyzer</b> — Detect suspicious network patterns</summary>

```bash
netsecops traffic-analyze --input traffic.csv --threshold 100
netsecops traffic-analyze --input traffic.csv --output traffic-report.json
```

**Detects:** Hosts with excessive connections · Suspicious port usage · Port distribution anomalies · Data transfer anomalies
</details>

<details>
<summary><b>🔍 DNS Analyzer</b> — Detect DGA domains & DNS tunneling</summary>

```bash
netsecops dns-analyze --input dns-logs.csv
netsecops dns-analyze --input dns-logs.csv --top 20 --output dns-report.json
```

**Detects:** DGA domains (high entropy, unusual character distribution) · DNS tunneling (long subdomains, excessive TXT queries) · Top queried domains with client counts
</details>

<details>
<summary><b>🔎 IP Reputation Checker</b> — Check IPs against threat intelligence</summary>

```bash
netsecops ip-check --input suspicious-ips.txt
netsecops ip-check --input ips.txt --threat-feed known-bad-ips.txt --output report.json
```

**Detects:** Threat intel matches · Bogon/RFC1918 in external traffic · Suspicious IP patterns (sequential, repeating)
</details>

<details>
<summary><b>🔐 Secrets Scanner</b> — Find leaked credentials in your code</summary>

```bash
netsecops scan-secrets --input ./my-project/
netsecops scan-secrets --input ./src/ --max-size 1024 --output secrets-report.json
```

**Finds:** AWS Keys · GitHub/Slack/Google/Stripe/SendGrid tokens · Private keys (RSA, EC, DSA) · Database URLs · Hardcoded passwords · JWT & Bearer tokens
</details>

<details>
<summary><b>🔄 Config Diff</b> — Compare configs & flag security regressions</summary>

```bash
netsecops config-diff --before old-rules.csv --after new-rules.csv
netsecops config-diff --before old.csv --after new.csv --output diff-report.json
```

**Flags:**
- 🔴 **CRITICAL:** deny→allow, source opened to ANY, new allow-any rules
- 🟠 **HIGH:** logging removed, risky ports opened, deny rules removed
- 🟢 **IMPROVED:** allow→deny, ANY restrictions added
</details>

<details>
<summary><b>🔑 Password Auditor</b> — Audit strength & check known breaches</summary>

```bash
netsecops password-audit --input passwords.txt
netsecops password-audit --input passwords.txt --hibp --output audit-report.json
```

**Checks:** Length & complexity scoring · Common password matching (top 100) · Sequential characters · Keyboard patterns · SHA1 hashes for HIBP k-anonymity API
</details>

<details>
<summary><b>🛡️ File Integrity Monitor (FIM)</b> — Detect unauthorized file changes</summary>

```bash
# Step 1: Create baseline
netsecops fim --input /etc/nginx/ --mode init --output baseline.json

# Step 2: Verify later
netsecops fim --input /etc/nginx/ --mode check --baseline baseline.json
```

**Detects:** 🔴 Modified files (hash changed) · 🟡 Removed files · 🔵 New files · 🟠 Size changes
</details>

---

## 🧪 Examples

The `examples/` directory contains sample data to try every module:

```bash
# ── Original Modules ──
netsecops audit-rules --input examples/sample-firewall-rules.csv
netsecops parse-logs --input examples/sample-proxy-logs.csv
netsecops pac-test --input examples/sample.pac --validate
netsecops traffic-analyze --input examples/sample-traffic.csv --threshold 3

# ── New Modules ──
netsecops dns-analyze --input examples/sample-dns-logs.csv
netsecops ip-check --input examples/sample-ips.txt --threat-feed examples/sample-threat-feed.txt
netsecops scan-secrets --input examples/
netsecops config-diff --before examples/sample-config-before.csv --after examples/sample-config-after.csv
netsecops password-audit --input examples/sample-passwords.txt --hibp
netsecops fim --input examples/ --mode init --output /tmp/baseline.json
```

---

## 🏢 Supported Vendors

| Vendor | Firewall Audit | Log Parsing | Notes |
|:--|:--:|:--:|:--|
| **Palo Alto** | ✅ | ✅ | CSV export from Panorama/firewall |
| **Fortinet** | ✅ | ✅ | FortiGate CSV logs |
| **Cisco ASA** | ✅ | 🔜 | ACL export |
| **Zscaler ZIA** | — | ✅ | NSS feed logs |
| **Forcepoint** | — | ✅ | Web Security logs |
| **BlueCoat/Symantec** | — | ✅ | ProxySG access logs |
| **Generic CSV** | ✅ | ✅ | Any CSV with matching headers |

---

## 🗺️ Roadmap

- [ ] 🔌 Zscaler ZIA API integration (URL lookup, policy management)
- [ ] 📋 Netskope log support
- [ ] 🔬 PCAP file analysis (native)
- [ ] 🧱 Check Point firewall support
- [ ] 📄 HTML report generation
- [ ] ⚙️ Config file for default settings
- [ ] 📡 Syslog/CEF input format
- [ ] 🔗 SIEM integration (Splunk, QRadar export)
- [ ] 🌐 HIBP online API integration
- [ ] 🐛 CVE feed aggregator module

---

## 🤝 Contributing

Contributions are welcome! See [**CONTRIBUTING.md**](CONTRIBUTING.md) for guidelines.

The easiest ways to contribute:
- **Add support for a new vendor** — see the wishlist in the contributing guide
- **Improve detection patterns** — especially for secrets scanner and DGA detection
- **Add new modules** — follow the existing pattern in `src/`

---

## 📜 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

**Built with 🦀 Rust for the Network Security community**

<sub>If this tool helped you, give it a ⭐ — it means a lot!</sub>

<br>

<a href="https://github.com/DBISHT4U/NetSecOPS/stargazers"><img src="https://img.shields.io/github/stars/DBISHT4U/NetSecOPS?style=social" alt="Stars"></a>
<a href="https://github.com/DBISHT4U/NetSecOPS/network/members"><img src="https://img.shields.io/github/forks/DBISHT4U/NetSecOPS?style=social" alt="Forks"></a>

</div>
