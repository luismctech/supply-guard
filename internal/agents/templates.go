package agents

func templateContent(id FileID) string {
	switch id {
	case CursorRule:
		return cursorRuleTemplate
	case AgentsMD:
		return agentsMDTemplate
	case SkillMD:
		return skillMDTemplate
	default:
		return ""
	}
}

const cursorRuleTemplate = `---
description: Supply chain security scanning with SupplyGuard
globs:
  - package.json
  - package-lock.json
  - requirements.txt
  - Pipfile
  - pyproject.toml
  - poetry.lock
  - Cargo.toml
  - Cargo.lock
  - pom.xml
  - build.gradle
  - "*.csproj"
  - packages.lock.json
  - supplyguard.yaml
  - .github/workflows/*.yml
  - .github/workflows/*.yaml
  - .npmrc
  - pip.conf
alwaysApply: false
---

# SupplyGuard — Supply Chain Security

When modifying dependency files, lock files, CI workflows, or install scripts, run a supply chain security scan.

## Scanning

` + "```" + `bash
# Quick scan with JSON output
supply-guard scan --output json --quiet

# Readable markdown report
supply-guard scan --output markdown --quiet

# Auto-fix patches
supply-guard scan --output diff --quiet > fixes.patch && git apply fixes.patch

# CI mode (fail on critical/high)
supply-guard scan --fail-on critical,high --output json --quiet
` + "```" + `

## MCP Server

SupplyGuard is available as an MCP server. Tools: scan, explain_finding, suggest_fix, list_checks, get_policy.

## Key Checks

- **SG001**: Lockfile must match package manifest
- **SG002**: Dangerous install scripts (preinstall, postinstall)
- **SG003**: Known malicious packages and C2 domains
- **SG006**: Typosquatting detection
- **SG008**: Package manager config hardening
- **SG009**: GitHub Actions must be pinned by SHA
- **SG011**: Version ranges should not be overly permissive

## When to Scan

- After adding or removing dependencies
- After modifying CI workflow files
- After updating lockfiles
- Before creating PRs that touch dependency files
`

const agentsMDTemplate = `# Supply Chain Security — SupplyGuard

This project uses [SupplyGuard](https://github.com/AlbertoMZCruz/supply-guard) for supply chain security scanning.

## Quick Reference

` + "```" + `bash
# Scan (JSON for parsing)
supply-guard scan --output json --quiet

# Scan (markdown for chat display)
supply-guard scan --output markdown --quiet

# Auto-fix patches
supply-guard scan --output diff --quiet > fixes.patch && git apply fixes.patch

# CI mode
supply-guard scan --fail-on critical,high --output json --quiet

# Baseline diffing (only new findings)
supply-guard scan --baseline baseline.json --output json --quiet
` + "```" + `

## Output Formats

| Format | Flag | Best for |
|--------|------|----------|
| table | --output table | Human terminal display |
| json | --output json | Programmatic parsing |
| sarif | --output sarif | GitHub Code Scanning, IDE |
| markdown | --output markdown | Chat display, PR comments |
| diff | --output diff | Auto-applying fixes via git apply |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Findings exceed --fail-on threshold |
| 2 | Scanner error |
| 10 | Critical findings present |
| 11 | High findings (no critical) |
| 12 | Medium findings (no critical/high) |

## JSON Schema

Output follows the schema at schema/scan-result.schema.json (if installed).
Key fields: check_id, severity, file, line, fingerprint, fix.

## MCP Tools

If configured as MCP server, these tools are available:
- scan — Run a full or targeted scan
- explain_finding — Detailed explanation of a check (check_id required)
- suggest_fix — Remediation steps for a finding (check_id required)
- list_checks — List all 12 security checks
- get_policy — Read active policy configuration
- install_agent_files — Install agent integration files into a project

## Checks

| ID | Description |
|----|-------------|
| SG001 | Lockfile integrity |
| SG002 | Install script detection |
| SG003 | IOC matching (malicious packages/domains) |
| SG004 | Dependency age |
| SG005 | Phantom dependencies |
| SG006 | Typosquatting |
| SG007 | Provenance verification |
| SG008 | Config hardening |
| SG009 | GitHub Actions SHA pinning |
| SG010 | Network call detection |
| SG011 | Version range permissiveness |
| SG012 | Unsafe CI install commands |
`

const skillMDTemplate = `# SupplyGuard Skill

Scan projects for supply chain security threats across npm, pip, Cargo, Maven, and NuGet ecosystems.

## When to Use

USE FOR: supply chain security scanning, dependency auditing, malicious package detection, typosquatting checks, lockfile integrity, install script analysis, CI workflow security, IOC matching.

DO NOT USE FOR: vulnerability scanning (CVE databases), license compliance, code quality analysis, SAST, runtime monitoring.

## Prerequisites

supply-guard binary must be installed and in PATH, or configured as MCP server.

## Usage

### Scan with JSON (best for parsing)
` + "```" + `bash
supply-guard scan --output json --quiet
` + "```" + `

### Scan with markdown (best for displaying)
` + "```" + `bash
supply-guard scan --output markdown --quiet
` + "```" + `

### Auto-fix
` + "```" + `bash
supply-guard scan --output diff --quiet > fixes.patch && git apply fixes.patch
` + "```" + `

### CI mode
` + "```" + `bash
supply-guard scan --fail-on critical,high --output json --quiet
` + "```" + `

## MCP Tools

- scan — Full or targeted scan (directory, checks[], format)
- explain_finding — Why a check matters (check_id, package)
- suggest_fix — Remediation steps (check_id, file, package, ecosystem)
- list_checks — All 12 checks with descriptions
- get_policy — Active policy configuration

## Interpreting Results

Each finding has:
- check_id (SG001-SG012): check type
- severity (critical/high/medium/low/info): urgency
- file + line: exact location
- fingerprint: stable ID for deduplication
- fix: machine-actionable suggestion (when available)

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean |
| 1 | Exceeds --fail-on threshold |
| 2 | Error |
| 10/11/12 | Critical/High/Medium findings |
`
