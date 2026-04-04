# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
| < latest | No       |

Only the latest release receives security updates. Upgrade to the latest version to stay protected.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities through one of these channels:

1. **GitHub Security Advisories** (preferred): Go to the [Security tab](https://github.com/AlbertoMZCruz/supply-guard/security/advisories/new) and create a private security advisory.
2. **Email**: Send details to the repository owner via their GitHub profile.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix release**: Critical issues within 14 days, others within 30 days

### Disclosure policy

We follow coordinated disclosure. Please allow us reasonable time to fix the issue before public disclosure. We will credit reporters in the release notes unless they prefer to remain anonymous.

## Security Measures

SupplyGuard implements the following security measures in its own codebase:

- **Safe file I/O**: All reads use `safefile.ReadFile` with symlink protection (`O_NOFOLLOW`), 50 MB size limits, and bounded directory traversal.
- **Input sanitization**: Terminal output sanitizes control characters to prevent ANSI injection from malicious package names.
- **HTTPS-only**: The `update` command enforces HTTPS and blocks redirect downgrades.
- **Pinned CI dependencies**: All GitHub Actions are pinned by SHA, not mutable tags.
- **Minimal dependencies**: Only `cobra`, `viper`, and `x/term` as direct dependencies.
- **Config injection protection**: Warns when a scanned repo contains a `supplyguard.yaml` that could disable checks.

## Supply Chain Security

This project uses itself (SupplyGuard) for supply chain scanning. The CI pipeline runs `supply-guard scan` on every PR to detect:

- Lockfile integrity issues
- Suspicious install scripts
- Known malicious packages
- Typosquatting attempts
- Unpinned GitHub Actions
- Permissive version ranges
