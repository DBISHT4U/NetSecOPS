# NetSecOPS Demo — VHS Recording
# Run: vhs netsecops-demo.tape

Output demo.gif
Set FontSize 13
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set Padding 15
Set TypingSpeed 35ms
Set CursorBlink false

Type "# ⚡ NetSecOPS — 11 modules, single binary, zero dependencies"
Enter
Sleep 1.5s

Type "netsecops audit-rules --input examples/sample-firewall-rules.csv"
Enter
Sleep 4s

Type "netsecops dns-analyze --input examples/sample-dns-logs.csv"
Enter
Sleep 4s

Type "netsecops ip-check --input examples/sample-ips.txt --threat-feed examples/sample-threat-feed.txt"
Enter
Sleep 4s

Type "netsecops config-diff --before examples/sample-config-before.csv --after examples/sample-config-after.csv"
Enter
Sleep 4s

Type "netsecops password-audit --input examples/sample-passwords.txt --hibp"
Enter
Sleep 4s

Type "netsecops scan-secrets --input examples/"
Enter
Sleep 3s

Type "# 🦀 11 modules. One binary. Blazing fast."
Enter
Sleep 2s
