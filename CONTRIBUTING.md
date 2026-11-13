# Contributing to NetSecOps

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repo
2. Clone your fork: `git clone https://github.com/your-username/netsecops.git`
3. Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
4. Build: `cargo build`
5. Run tests: `cargo test`

## How to Contribute

### Adding a New Vendor Parser
The most common contribution — adding support for a new firewall/proxy vendor:

1. Create a new module or extend an existing one in the relevant directory
2. Add CSV field mappings using serde aliases
3. Add sample data in `examples/`
4. Add tests in `tests/`
5. Update README with the new vendor

### Reporting Bugs
Open an issue with:
- Command you ran
- Input file format (redact sensitive data)
- Expected vs actual output
- OS and netsecops version (`netsecops --version`)

### Feature Requests
Open an issue tagged `enhancement` with:
- What problem does it solve?
- Who benefits?
- Example usage

## Code Guidelines

- Run `cargo clippy` before committing
- Run `cargo fmt` for formatting
- Add tests for new features
- Keep error messages user-friendly
- Use `anyhow` for error handling

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Run tests: `cargo test`
4. Run linter: `cargo clippy`
5. Push and open a PR against `main`

## Vendor Support Wishlist

We'd love contributions for these vendors:
- [ ] Check Point
- [ ] Sophos XG
- [ ] SonicWall
- [ ] Juniper SRX
- [ ] Cisco Umbrella
- [ ] McAfee Web Gateway
- [ ] Symantec ProxySG (Blue Coat)
- [ ] F5 BIG-IP

## License

By contributing, you agree your contributions are licensed under MIT.
