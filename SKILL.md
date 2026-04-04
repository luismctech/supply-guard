# SupplyGuard Skill

Scan projects for supply chain security threats across npm, pip, Cargo, Maven, and NuGet ecosystems.

## When to Use

USE FOR: supply chain security scanning, dependency auditing, malicious package detection, typosquatting checks, lockfile integrity, install script analysis, CI workflow security, IOC matching, phantom dependency detection, version range analysis, provenance verification.

DO NOT USE FOR: vulnerability scanning (CVE databases), license compliance checking, code quality analysis, static application security testing (SAST), runtime security monitoring.

## Prerequisites

- `supply-guard` binary must be installed and available in PATH
- Alternatively, configure as MCP server: `{ "command": "supply-guard", "args": ["mcp"] }`

## Usage

### Quick Scan (JSON for parsing)

```bash
supply-guard scan --output json --quiet
```

### Scan with Readable Report

```bash
supply-guard scan --output markdown --quiet
```

### Scan with Auto-Fix Patches

```bash
supply-guard scan --output diff --quiet > fixes.patch && git apply fixes.patch
```

### CI Mode (fail on critical/high)

```bash
supply-guard scan --fail-on critical,high --output json --quiet
```

### MCP Tools

When available as MCP server, use these tools:
- `scan` — Run a full or targeted scan
- `explain_finding` — Get detailed explanation of a specific finding
- `suggest_fix` — Get actionable fix for a finding
- `list_checks` — List all available security checks
- `get_policy` — Read current policy configuration

## Interpreting Results

Each finding has:
- `check_id` (SG001-SG012): identifies the check type
- `severity` (critical/high/medium/low/info): urgency level
- `file` + `line`: exact location in the codebase
- `fingerprint`: stable identifier for tracking across scans
- `fix`: machine-actionable suggestion (when available)

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan or below threshold |
| 1 | Findings exceed --fail-on threshold |
| 2 | Scanner error |
| 10/11/12 | Critical/High/Medium findings present |

## Checks Reference

| ID | What it detects |
|----|-----------------|
| SG001 | Missing or inconsistent lockfiles |
| SG002 | Dangerous lifecycle scripts (preinstall, postinstall) |
| SG003 | Known malicious packages, C2 domains, suspicious maintainer emails |
| SG004 | Dependencies published less than 7 days ago |
| SG005 | Imports of packages not declared in manifest |
| SG006 | Package names similar to popular packages (typosquatting) |
| SG007 | Missing integrity hashes or provenance attestations |
| SG008 | Package manager not configured with security defaults |
| SG009 | GitHub Actions using mutable tags instead of SHA pins |
| SG010 | Network/exec calls in build scripts |
| SG011 | Overly permissive version ranges (wildcards, >= ranges) |
| SG012 | Unsafe install commands in CI workflows (curl pipe sh, etc.) |
