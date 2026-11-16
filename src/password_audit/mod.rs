#[allow(unused_imports, unused_variables, dead_code, clippy::needless_return)]
use anyhow::{Context, Result};
use colored::*;
use serde::Serialize;
use sha1::{Digest as Sha1Digest, Sha1};
use std::collections::HashSet;
use std::fs;
use tabled::{Table, Tabled};

/// Common weak passwords (top 100 baseline)
const COMMON_PASSWORDS: &[&str] = &[
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass",
    "maggie", "159753", "aaaaaa", "ginger", "princess",
    "joshua", "cheese", "amanda", "summer", "love",
    "ashley", "nicole", "chelsea", "biteme", "matthew",
    "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "admin", "password1",
    "welcome", "welcome1", "p@ssw0rd", "passw0rd", "admin123",
];

#[derive(Debug, Serialize, Tabled, Clone)]
struct PasswordResult {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Password")]
    masked: String,
    #[tabled(rename = "Length")]
    length: usize,
    #[tabled(rename = "Strength")]
    strength: String,
    #[tabled(rename = "Score")]
    score: String,
    #[tabled(rename = "Issues")]
    issues: String,
}

#[derive(Debug, Serialize, Tabled)]
struct HibpEntry {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Password")]
    masked: String,
    #[tabled(rename = "SHA1 Prefix (k-anonymity)")]
    sha1_prefix: String,
    #[tabled(rename = "Full SHA1")]
    sha1_full: String,
}

#[derive(Debug, Serialize)]
struct AuditReport {
    total_passwords: usize,
    weak_count: usize,
    medium_count: usize,
    strong_count: usize,
    common_match_count: usize,
    results: Vec<PasswordResult>,
}

fn mask_password(pw: &str) -> String {
    if pw.len() <= 2 {
        "*".repeat(pw.len())
    } else {
        format!("{}{}{}",
            &pw[..1],
            "*".repeat(pw.len() - 2),
            &pw[pw.len()-1..])
    }
}

fn sha1_hash(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode_upper(result)
}

fn check_password_strength(password: &str, common_set: &HashSet<&str>) -> (u8, String, Vec<String>) {
    let mut score: u8 = 0;
    let mut issues: Vec<String> = Vec::new();

    let len = password.len();
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    let unique_chars: HashSet<char> = password.chars().collect();

    // Length scoring
    if len >= 16 { score += 3; }
    else if len >= 12 { score += 2; }
    else if len >= 8 { score += 1; }
    else { issues.push("Too short (<8)".to_string()); }

    // Character variety
    if has_lower { score += 1; }
    if has_upper { score += 1; }
    if has_digit { score += 1; }
    if has_special { score += 2; }

    if !has_upper { issues.push("No uppercase".to_string()); }
    if !has_digit { issues.push("No digits".to_string()); }
    if !has_special { issues.push("No special chars".to_string()); }

    // Unique character ratio
    let uniqueness = unique_chars.len() as f64 / len.max(1) as f64;
    if uniqueness < 0.4 {
        issues.push("Too repetitive".to_string());
    } else if uniqueness > 0.7 {
        score += 1;
    }

    // Common password check
    if common_set.contains(password.to_lowercase().as_str()) {
        score = score.saturating_sub(5);
        issues.push("Common password!".to_string());
    }

    // Sequential chars (abc, 123)
    let chars: Vec<char> = password.chars().collect();
    let mut sequential = 0;
    for i in 0..chars.len().saturating_sub(2) {
        if chars[i] as u32 + 1 == chars[i+1] as u32
            && chars[i+1] as u32 + 1 == chars[i+2] as u32
        {
            sequential += 1;
        }
    }
    if sequential > 1 {
        issues.push("Sequential chars".to_string());
        score = score.saturating_sub(1);
    }

    // Keyboard patterns
    let keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "qazwsx"];
    for pattern in keyboard_patterns {
        if password.to_lowercase().contains(pattern) {
            issues.push("Keyboard pattern".to_string());
            score = score.saturating_sub(2);
            break;
        }
    }

    let strength = if score >= 7 {
        "🟢 STRONG".to_string()
    } else if score >= 4 {
        "🟡 MEDIUM".to_string()
    } else {
        "🔴 WEAK".to_string()
    };

    (score, strength, issues)
}

pub fn run(input: &str, output: Option<&str>, show_hibp: bool) -> Result<()> {
    println!("{}", "🔑 Password Auditor".cyan().bold());
    println!("{}", "=".repeat(60).dimmed());

    let content = fs::read_to_string(input)
        .with_context(|| format!("Failed to read password list: {}", input))?;

    let passwords: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if passwords.is_empty() {
        println!("{}", "⚠ No passwords found in file.".yellow());
        return Ok(());
    }

    println!("  Loaded {} passwords from {}\n", passwords.len().to_string().white().bold(), input);

    let common_set: HashSet<&str> = COMMON_PASSWORDS.iter().copied().collect();

    let mut results: Vec<PasswordResult> = Vec::new();
    let mut weak = 0usize;
    let mut medium = 0usize;
    let mut strong = 0usize;
    let mut common_matches = 0usize;

    for (i, pw) in passwords.iter().enumerate() {
        let (score, strength, issues) = check_password_strength(pw, &common_set);

        if strength.contains("WEAK") { weak += 1; }
        else if strength.contains("MEDIUM") { medium += 1; }
        else { strong += 1; }

        if common_set.contains(pw.to_lowercase().as_str()) {
            common_matches += 1;
        }

        results.push(PasswordResult {
            index: i + 1,
            masked: mask_password(pw),
            length: pw.len(),
            strength,
            score: format!("{}/10", score),
            issues: if issues.is_empty() {
                "None".to_string()
            } else {
                issues.join(", ")
            },
        });
    }

    // Display strength results
    println!("{}", "🔍 Password Strength Analysis".green().bold());
    let table = Table::new(&results).to_string();
    println!("{}", table);

    // Summary
    println!("\n{}", "📊 Summary".green().bold());
    println!("  🟢 Strong:  {}", strong.to_string().green().bold());
    println!("  🟡 Medium:  {}", medium.to_string().yellow().bold());
    println!("  🔴 Weak:    {}", weak.to_string().red().bold());
    println!("  📋 Common password matches: {}", common_matches.to_string().red().bold());

    // HIBP hash generation
    if show_hibp {
        println!("\n{}", "🌐 HIBP k-Anonymity Hashes".yellow().bold());
        println!("  Use the SHA1 prefix (first 5 chars) with the HIBP range API:");
        println!("  {}\n", "https://api.pwnedpasswords.com/range/{PREFIX}".dimmed());

        let hibp_entries: Vec<HibpEntry> = passwords
            .iter()
            .enumerate()
            .map(|(i, pw)| {
                let hash = sha1_hash(pw);
                HibpEntry {
                    index: i + 1,
                    masked: mask_password(pw),
                    sha1_prefix: hash[..5].to_string(),
                    sha1_full: hash,
                }
            })
            .collect();

        let hibp_table = Table::new(&hibp_entries).to_string();
        println!("{}", hibp_table);
    }

    // Export
    if let Some(out_path) = output {
        let report = AuditReport {
            total_passwords: passwords.len(),
            weak_count: weak,
            medium_count: medium,
            strong_count: strong,
            common_match_count: common_matches,
            results,
        };
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(out_path, &json)
            .with_context(|| format!("Failed to write report: {}", out_path))?;
        println!("\n{} Report exported to {}", "📁".green(), out_path.white().bold());
    }

    println!("\n{}", "✅ Password audit complete.".green().bold());
    Ok(())
}
