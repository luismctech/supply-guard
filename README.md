# SupplyGuard

Supply chain security scanner that detects what vulnerability scanners miss.

**Zero dependencies. Works offline. Single binary.**

SupplyGuard complements tools like Trivy, Grype, and Snyk by focusing on threats they don't catch: malicious packages, suspicious install scripts, typosquatting, IOC matches, and policy violations.

## Why

In March 2026, the Axios npm package (100M+ weekly downloads) was compromised via account hijacking. The malicious version included a RAT payload that self-destructed after execution. Traditional CVE scanners didn't detect it because it wasn't a vulnerability — it was a supply chain attack.

SupplyGuard is built to catch exactly these kinds of threats.

## What it detects

| Check | ID | Description |
|-------|-----|-------------|
| Lockfile integrity | SG001 | Missing, corrupted, or out-of-sync lockfiles |
| Install scripts | SG002 | Lifecycle scripts (postinstall, preinstall) with suspicious patterns |
| IOC matching | SG003 | Known malicious packages, C2 domains, and suspicious maintainer emails |
| Dependency age | SG004 | Packages published less than N days ago |
| Phantom deps | SG005 | Dependencies in manifest but never imported in source |
| Typosquatting | SG006 | Package names suspiciously similar to popular packages |
| Provenance | SG007 | Missing integrity hashes, checksums, or SLSA/Sigstore attestations |
| Config hardening | SG008 | Insecure package manager configuration |
| Actions pinning | SG009 | GitHub Actions using tags instead of SHA pins |
| Network calls | SG010 | Scripts making network requests, using exec APIs, or contacting C2 domains |
| Version ranges | SG011 | Permissive or unbounded version ranges in dependency manifests |
| CI install audit | SG012 | Unsafe install commands in CI workflows (e.g. `npm install` instead of `npm ci`) |

## Supported ecosystems

- **npm** (package.json, package-lock.json, .npmrc)
- **pip/PyPI** (requirements.txt, poetry.lock, pyproject.toml, .pth files)
- **Cargo** (Cargo.toml, Cargo.lock, build.rs)
- **NuGet** (.csproj, packages.lock.json)
- **Maven** (pom.xml)
- **Gradle** (build.gradle, verification-metadata.xml)

## Quick start

```bash
# Scan current directory
supply-guard scan

# Scan a specific project
supply-guard scan /path/to/project

# JSON output for CI parsing
supply-guard scan -o json

# SARIF output for GitHub Code Scanning / VS Code
supply-guard scan -o sarif

# Fail CI on critical or high findings
supply-guard scan --fail-on critical,high

# Initialize hardening config in your project
supply-guard init
```

## Installation

### Quick install (recommended)

```bash
curl -sSf https://raw.githubusercontent.com/AlbertoMZCruz/supply-guard/main/install.sh | sh
```

This auto-detects your OS and architecture, downloads the latest release, and installs to `/usr/local/bin`.

### GitHub Releases

Download pre-built binaries for Linux, macOS, and Windows (amd64/arm64) from [GitHub Releases](https://github.com/AlbertoMZCruz/supply-guard/releases).

### Docker

```bash
docker run --rm -v $(pwd):/project ghcr.io/albertomzcruz/supply-guard scan /project
```

### From source

```bash
go install github.com/AlbertoMZCruz/supply-guard/cmd/supply-guard@latest
```

## Configuration

Create `supplyguard.yaml` in your project root (or run `supply-guard init`):

```yaml
output: table

fail_on:
  - critical
  - high

ecosystems:
  npm:
    enabled: true
  pip:
    enabled: true

checks:
  dependency_age_days: 7
  # Version range strictness: exact, conservative, permissive
  version_range_strictness: conservative
  # Disable specific checks by ID (SG001-SG012)
  # disabled:
  #   - SG005

# Ignore packages entirely (all checks)
ignore:
  - some-trusted-internal-package

# Granular ignore rules (all non-empty fields must match)
# ignore_rules:
#   - check: SG002
#     package: esbuild
#     reason: "trusted build tool"
#   - check: SG009
#     file: ".github/workflows/sonarcloud.yml"
#     reason: "pinning managed by Renovate"
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install supply-guard
  run: curl -sSf https://raw.githubusercontent.com/AlbertoMZCruz/supply-guard/main/install.sh | sh

- name: Supply chain security scan
  run: supply-guard scan --fail-on critical,high -o sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Docker (any CI)

```bash
docker run --rm -v $(pwd):/project ghcr.io/albertomzcruz/supply-guard scan /project --fail-on critical,high
```

Works with GitHub Actions, Azure DevOps, GitLab CI, Jenkins, and Bitbucket Pipelines. SupplyGuard auto-detects CI environments and adapts output accordingly.

## Security features

- **Safe file reading**: All file reads go through `safefile.ReadFile` with O_NOFOLLOW (symlink race prevention), 50 MB size cap, and `LimitReader` enforcement.
- **Bounded directory walking**: `safefile.WalkDir` enforces max depth (20) and file count (50,000) limits to prevent resource exhaustion from malicious repos.
- **Terminal escape protection**: All untrusted data in table output is sanitized to prevent ANSI escape injection from malicious package names.
- **Config injection warning**: Detects when a scanned repo plants a `supplyguard.yaml` that could disable checks. Use `--config` to specify a trusted path, or set `SUPPLYGUARD_TRUST_PROJECT_CONFIG=true` to suppress.
- **HTTPS-only updates**: The `update` command enforces HTTPS and blocks redirect downgrades.
- **Updatable threat intelligence**: `supply-guard update` downloads the latest IOC database to `~/.config/supplyguard/iocs.json`, which is automatically preferred over the embedded data.

## Design principles

- **Offline-first**: All IOC data is embedded in the binary. Works without internet.
- **Zero trust**: Does not depend on npm audit, pip-audit, or any external tool.
- **Complementary**: Does not scan for CVEs (Trivy/Grype do that). Detects behavioral threats.
- **Fail-open by default**: Reports findings locally without blocking. Use `--fail-on` in CI to gate.
- **Zero config needed**: `supply-guard scan .` works out of the box with secure defaults.

## Updating threat intelligence

The embedded IOC database covers known threats at build time. To get the latest:

```bash
supply-guard update
```

This saves the updated database to `~/.config/supplyguard/iocs.json`. SupplyGuard automatically uses the disk version when available, falling back to the embedded data if not.

## License

MIT
