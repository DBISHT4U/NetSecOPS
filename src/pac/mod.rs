use anyhow::{Context, Result};
use colored::*;
use regex::Regex;
use std::fs;

#[derive(Debug)]
struct PacIssue {
    line: usize,
    severity: String,
    message: String,
}

fn validate_pac(content: &str) -> Vec<PacIssue> {
    let mut issues = Vec::new();

    // Check for FindProxyForURL function
    if !content.contains("FindProxyForURL") {
        issues.push(PacIssue {
            line: 0,
            severity: "CRITICAL".to_string(),
            message: "Missing FindProxyForURL function — not a valid PAC file".to_string(),
        });
    }

    // Check for function signature
    let func_re = Regex::new(r"function\s+FindProxyForURL\s*\(\s*\w+\s*,\s*\w+\s*\)").unwrap();
    if !func_re.is_match(content) && content.contains("FindProxyForURL") {
        issues.push(PacIssue {
            line: 0,
            severity: "HIGH".to_string(),
            message: "FindProxyForURL function signature may be malformed".to_string(),
        });
    }

    // Check for return statements
    if !content.contains("return") {
        issues.push(PacIssue {
            line: 0,
            severity: "CRITICAL".to_string(),
            message: "No return statement found — PAC must return proxy string".to_string(),
        });
    }

    // Line-by-line checks
    let ip_in_proxy = Regex::new(r"PROXY\s+\d+\.\d+\.\d+\.\d+").unwrap();
    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        // Check for DIRECT return
        if trimmed.contains("DIRECT") && !trimmed.contains("\"DIRECT\"") && !trimmed.contains("'DIRECT'") {
            // It's okay in a return string like "DIRECT; PROXY x"
        }

        // Check for common PAC functions used correctly
        let pac_functions = [
            "isPlainHostName",
            "dnsDomainIs",
            "localHostOrDomainIs",
            "isResolvable",
            "isInNet",
            "dnsResolve",
            "myIpAddress",
            "dnsDomainLevels",
            "shExpMatch",
            "weekdayRange",
            "dateRange",
            "timeRange",
        ];

        for func in &pac_functions {
            if trimmed.contains(func) && !trimmed.contains(&format!("{}(", func)) {
                issues.push(PacIssue {
                    line: line_num,
                    severity: "MEDIUM".to_string(),
                    message: format!("{} used without parentheses — possible syntax error", func),
                });
            }
        }

        // Check for hardcoded IPs in proxy strings (potential issue)
        if ip_in_proxy.is_match(trimmed) {
            issues.push(PacIssue {
                line: line_num,
                severity: "LOW".to_string(),
                message: "Hardcoded IP in PROXY directive — consider using hostname".to_string(),
            });
        }

        // Check for alert/document/window (not valid in PAC context)
        let browser_apis = ["alert(", "document.", "window.", "console."];
        for api in &browser_apis {
            if trimmed.contains(api) {
                issues.push(PacIssue {
                    line: line_num,
                    severity: "HIGH".to_string(),
                    message: format!(
                        "Browser API '{}' is not available in PAC execution context",
                        api.trim_end_matches(&['.', '('][..])
                    ),
                });
            }
        }

        // Check for unreachable code after return
        if trimmed.starts_with("return ") && !trimmed.ends_with('{') {
            // Check if next non-empty line is code (not a closing brace)
            let remaining_lines: Vec<&str> = content
                .lines()
                .skip(i + 1)
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();
            if let Some(next) = remaining_lines.first() {
                if !next.starts_with('}')
                    && !next.starts_with("//")
                    && !next.starts_with("function")
                    && !next.starts_with("else")
                {
                    // Could be unreachable but also could be in different scope
                }
            }
        }

        // Check for missing semicolons in return statements
        if trimmed.starts_with("return ")
            && !trimmed.ends_with(';')
            && !trimmed.ends_with('{')
            && !trimmed.ends_with(',')
        {
            issues.push(PacIssue {
                line: line_num,
                severity: "LOW".to_string(),
                message: "Return statement missing semicolon".to_string(),
            });
        }
    }

    // Check for PROXY format validity
    let proxy_re = Regex::new(r#"PROXY\s+[\w.\-]+:\d+"#).unwrap();
    let has_proxy_keyword = content.contains("PROXY ");
    if has_proxy_keyword && !proxy_re.is_match(content) {
        issues.push(PacIssue {
            line: 0,
            severity: "HIGH".to_string(),
            message: "PROXY directive found but format may be invalid (expected PROXY host:port)"
                .to_string(),
        });
    }

    issues
}

fn test_url_against_pac(content: &str, url: &str) -> String {
    // Simple static analysis of PAC file to determine likely proxy for URL
    let host = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(url);

    let mut result = String::new();

    // Check for shExpMatch patterns
    let sh_re = Regex::new(r#"shExpMatch\s*\(\s*\w+\s*,\s*["']([^"']+)["']\s*\)"#).unwrap();
    for cap in sh_re.captures_iter(content) {
        let pattern = &cap[1];
        let pattern_regex = pattern
            .replace('.', r"\.")
            .replace('*', ".*")
            .replace('?', ".");
        if let Ok(re) = Regex::new(&format!("^{}$", pattern_regex)) {
            if re.is_match(host) || re.is_match(url) {
                result.push_str(&format!("  🎯 Matches shExpMatch pattern: {}\n", pattern));
            }
        }
    }

    // Check for dnsDomainIs patterns
    let dns_re =
        Regex::new(r#"dnsDomainIs\s*\(\s*\w+\s*,\s*["']([^"']+)["']\s*\)"#).unwrap();
    for cap in dns_re.captures_iter(content) {
        let domain_pattern = &cap[1];
        if host.ends_with(domain_pattern) || host == domain_pattern.trim_start_matches('.') {
            result.push_str(&format!(
                "  🎯 Matches dnsDomainIs: {}\n",
                domain_pattern
            ));
        }
    }

    // Check for isPlainHostName
    if content.contains("isPlainHostName") && !host.contains('.') {
        result.push_str("  🎯 Matches isPlainHostName (no dots in hostname)\n");
    }

    // Check for isInNet patterns
    let innet_re = Regex::new(
        r#"isInNet\s*\([^,]+,\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*\)"#,
    )
    .unwrap();
    for cap in innet_re.captures_iter(content) {
        result.push_str(&format!(
            "  📡 isInNet check: {}/{} (requires DNS resolution)\n",
            &cap[1], &cap[2]
        ));
    }

    // Extract return statements for context
    let return_re = Regex::new(r#"return\s+["']([^"']+)["']"#).unwrap();
    let returns: Vec<String> = return_re
        .captures_iter(content)
        .map(|c| c[1].to_string())
        .collect();

    if !returns.is_empty() {
        result.push_str("\n  📋 Possible proxy paths in this PAC:\n");
        for (i, ret) in returns.iter().enumerate() {
            result.push_str(&format!("     {}. {}\n", i + 1, ret));
        }
    }

    if result.is_empty() {
        result = "  ℹ️  No direct pattern match found — likely falls to default return".to_string();
    }

    result
}

pub fn run(input: &str, url: Option<&str>, validate: bool, url_list: Option<&str>) -> Result<()> {
    println!(
        "{} {}",
        "🌐 PAC File Tool:".green().bold(),
        input.yellow()
    );
    println!();

    let content =
        fs::read_to_string(input).with_context(|| format!("Failed to read PAC file: {}", input))?;

    // Always validate
    if validate || url.is_none() {
        println!("  {}", "━━━ PAC VALIDATION ━━━".white().bold());

        let issues = validate_pac(&content);

        if issues.is_empty() {
            println!("  {} No issues found — PAC file looks good!", "✅".green());
        } else {
            let critical = issues.iter().filter(|i| i.severity == "CRITICAL").count();
            let high = issues.iter().filter(|i| i.severity == "HIGH").count();
            let medium = issues.iter().filter(|i| i.severity == "MEDIUM").count();
            let low = issues.iter().filter(|i| i.severity == "LOW").count();

            println!(
                "  Found {} issue(s): {} critical, {} high, {} medium, {} low\n",
                issues.len(),
                critical.to_string().red(),
                high.to_string().yellow(),
                medium.to_string().bright_yellow(),
                low.to_string().green()
            );

            for issue in &issues {
                let severity_colored = match issue.severity.as_str() {
                    "CRITICAL" => issue.severity.red().bold(),
                    "HIGH" => issue.severity.yellow().bold(),
                    "MEDIUM" => issue.severity.bright_yellow(),
                    _ => issue.severity.green(),
                };
                let line_info = if issue.line > 0 {
                    format!("Line {}", issue.line)
                } else {
                    "Global".to_string()
                };
                println!(
                    "  [{}] {} — {}",
                    severity_colored, line_info, issue.message
                );
            }
        }
        println!();
    }

    // Test a single URL
    if let Some(test_url) = url {
        println!(
            "  {} Testing URL: {}\n",
            "🔍".cyan(),
            test_url.yellow()
        );
        let result = test_url_against_pac(&content, test_url);
        println!("{}", result);
    }

    // Test multiple URLs
    if let Some(url_file) = url_list {
        let urls = fs::read_to_string(url_file)
            .with_context(|| format!("Failed to read URL list: {}", url_file))?;
        let url_vec: Vec<&str> = urls
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

        println!(
            "  {} Testing {} URLs from: {}\n",
            "🔍".cyan(),
            url_vec.len(),
            url_file.yellow()
        );

        for test_url in url_vec {
            println!("  {} {}", "→".cyan(), test_url.white().bold());
            let result = test_url_against_pac(&content, test_url);
            println!("{}", result);
        }
    }

    Ok(())
}
