# SupplyGuard Skill

Scan projects for supply chain security threats across npm, pip, Cargo, Maven, and NuGet ecosystems.

## When to Use

USE FOR: supply chain security scanning, dependency auditing, malicious package detection, typosquatting checks, lockfile integrity, install script analysis, CI workflow security, IOC matching, phantom dependency detection, version range analysis, provenance verification, generating security reports for PRs.

DO NOT USE FOR: vulnerability scanning (CVE databases), license compliance checking, code quality analysis, static application security testing (SAST), runtime security monitoring.

## Prerequisites

`supply-guard` binary must be installed and available in PATH.

Install options:

```bash
# Quick install (Linux/macOS)
curl -sSf https://raw.githubusercontent.com/AlbertoMZCruz/supply-guard/main/install.sh | sh

# From source
go install github.com/AlbertoMZCruz/supply-guard/cmd/supply-guard@latest

# Docker
docker run --rm -v $(pwd):/project ghcr.io/albertomzcruz/supply-guard scan /project
```

Alternatively, configure as an MCP server (no shell commands needed):

```json
{
  "mcpServers": {
    "supply-guard": {
      "command": "supply-guard",
      "args": ["mcp"]
    }
  }
}
```

## Usage via CLI

### Scan with JSON output (best for parsing)

```bash
supply-guard scan --output json --quiet
```

### Scan with markdown (best for displaying to the user)

```bash
supply-guard scan --output markdown --quiet
```

### Auto-fix with unified diff patches

```bash
supply-guard scan --output diff --quiet > fixes.patch && git apply fixes.patch
```

### CI mode (fail on critical/high)

```bash
supply-guard scan --fail-on critical,high --output json --quiet
```

### Only show new findings vs. a baseline

```bash
supply-guard scan --baseline baseline.json --output json --quiet
```

### Watch mode (continuous scanning on file changes)

```bash
supply-guard scan --watch
```

### Generate reports from saved results

```bash
supply-guard scan --output json --quiet > scan-result.json
supply-guard report scan-result.json -f pr-comment
supply-guard report scan-result.json -f executive-summary
supply-guard report scan-result.json -f commit-message
supply-guard report scan-result.json -f developer-brief
```

## Usage via MCP

When configured as an MCP server, use these tools:

### `scan`

Run a full or targeted scan. All parameters optional.

```json
{ "directory": ".", "checks": ["SG001", "SG006"], "format": "markdown" }
```

### `explain_finding`

Get a detailed explanation of a check with risk assessment, attack vectors, and real-world examples.

```json
{ "check_id": "SG006", "package": "lod4sh" }
```

### `suggest_fix`

Get step-by-step remediation with code examples and config snippets.

```json
{ "check_id": "SG009", "file": ".github/workflows/ci.yml", "ecosystem": "ci" }
```

### `list_checks`

List all 12 security checks with descriptions and applicable ecosystems.

```json
{}
```

### `get_policy`

Read the active SupplyGuard policy configuration.

```json
{}
```

### `install_agent_files`

Install agent integration files (rules, MCP configs, docs) into a project.

```json
{ "directory": ".", "files": ["cursor-rule", "cursor-mcp"] }
```

## Installing Agent Files via CLI

```bash
supply-guard agents install              # All files
supply-guard agents install --cursor     # Cursor rule + MCP config + SKILL.md
supply-guard agents install --vscode     # VS Code MCP config
supply-guard agents install --docs       # AGENTS.md + SKILL.md
supply-guard agents list                 # Check install status
```

## Interpreting Results

Each finding has:

- `check_id` (SG001-SG012): identifies the check type
- `severity` (critical/high/medium/low/info): urgency level
- `file` + `line`: exact location in the codebase
- `fingerprint`: stable identifier for tracking across scans
- `fix`: machine-actionable fix suggestion (when available)
  - `fix.type`: replace, delete, add, config_change, command
  - `fix.old_content` / `fix.new_content`: for deterministic replacements
  - `fix.description`: human-readable instructions when not deterministic

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan or below threshold |
| 1 | Findings exceed `--fail-on` threshold |
| 2 | Scanner error |
| 10 | Critical findings present |
| 11 | High findings present (no critical) |
| 12 | Medium findings present (no critical/high) |

## Checks Reference

| ID | What it detects | Ecosystems |
|----|-----------------|------------|
| SG001 | Missing or inconsistent lockfiles | npm, pip, cargo |
| SG002 | Dangerous lifecycle scripts (preinstall, postinstall) | npm, pip, cargo |
| SG003 | Known malicious packages, C2 domains, suspicious maintainer emails | all |
| SG004 | Dependencies published less than 7 days ago | npm |
| SG005 | Imports of packages not declared in manifest | npm |
| SG006 | Package names similar to popular packages (typosquatting) | all |
| SG007 | Missing integrity hashes or provenance attestations | all, ci |
| SG008 | Package manager not configured with security defaults | npm, pip |
| SG009 | GitHub Actions using mutable tags instead of SHA pins | ci |
| SG010 | Network/exec calls in build scripts | all |
| SG011 | Overly permissive version ranges (wildcards, >= ranges) | all |
| SG012 | Unsafe install commands in CI workflows (curl pipe sh, etc.) | ci |
