# SupplyGuard — Agent Instructions

SupplyGuard is an offline supply-chain security scanner for npm, pip, Cargo, Maven, and NuGet.
It detects malicious packages, typosquatting, phantom dependencies, IOC matches, and policy violations.

## Quick Reference

```bash
# Scan current directory (human-readable)
supply-guard scan

# Scan with JSON output (best for parsing)
supply-guard scan --output json --quiet

# Scan with markdown output (best for chat display)
supply-guard scan --output markdown --quiet

# Scan with fix suggestions as unified diff
supply-guard scan --output diff --quiet

# Scan specific directory
supply-guard scan /path/to/project --output json -q

# Fail on critical/high findings (CI mode)
supply-guard scan --fail-on critical,high --output json -q
```

## Output Formats

| Format | Flag | Best for |
|--------|------|----------|
| `table` | `--output table` | Human terminal display |
| `json` | `--output json` | Programmatic parsing, automation |
| `sarif` | `--output sarif` | GitHub Code Scanning, IDE integration |
| `markdown` | `--output markdown` | Chat display, PR comments |
| `diff` | `--output diff` | Auto-applying fixes via `git apply` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no threshold violations |
| 1 | Findings exceed `--fail-on` severity threshold |
| 2 | Error (bad config, invalid path, scan failure) |
| 10 | Critical findings present |
| 11 | High findings present (no critical) |
| 12 | Medium findings present (no critical/high) |

## JSON Output Schema

The JSON output follows the schema at `schema/scan-result.schema.json`.

Key fields in each finding:
- `check_id`: SG001-SG012 identifier
- `severity`: critical, high, medium, low, info
- `file`, `line`: exact location
- `fingerprint`: stable hash for deduplication
- `fix`: machine-actionable fix suggestion (when available)
  - `fix.type`: replace, delete, add, config_change, command
  - `fix.old_content`, `fix.new_content`: for deterministic fixes
  - `fix.description`: for judgment-required fixes

## Agent Workflows

### Workflow 1: Scan and Report

```bash
supply-guard scan --output json -q | jq '.findings[] | select(.severity == "critical" or .severity == "high")'
```

### Workflow 2: Auto-Fix

```bash
supply-guard scan --output diff -q > fixes.patch
git apply fixes.patch
```

### Workflow 3: Baseline Diffing

```bash
# Save baseline
supply-guard scan --output json -q > baseline.json
# After changes, compare
supply-guard scan --output json -q > current.json
# Compare by fingerprints to find new findings
```

### Workflow 4: PR Comment

```bash
supply-guard scan --output markdown -q > report.md
```

## MCP Integration

SupplyGuard exposes an MCP server for direct tool integration:

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

Available MCP tools: `scan`, `explain_finding`, `suggest_fix`, `list_checks`, `get_policy`.

## Check IDs

| ID | Description |
|----|-------------|
| SG001 | Lockfile integrity verification |
| SG002 | Install script detection |
| SG003 | Known malicious package/domain match (IOC) |
| SG004 | Dependency age check |
| SG005 | Phantom dependency detection |
| SG006 | Typosquatting detection |
| SG007 | Provenance verification |
| SG008 | Package manager config hardening |
| SG009 | GitHub Actions SHA pinning |
| SG010 | Network call detection in scripts |
| SG011 | Version range permissiveness |
| SG012 | Unsafe CI install commands |

## Project Layout

```
cmd/supply-guard/     Entry point
internal/
  analyzer/           Per-ecosystem analyzers (npm, pip, cargo, maven, nuget)
  check/              Shared check logic (IOC, typosquat, provenance, etc.)
  cmd/                CLI commands (scan, init, update, version, mcp)
  config/             Configuration loading
  engine/             Scan orchestrator
  mcp/                MCP server implementation
  policy/             Policy engine
  report/             Output formatters (table, json, sarif, markdown, diff)
  safefile/           Safe file I/O (symlink protection, size limits)
  types/              Core types (Finding, ScanResult, Severity, CheckID)
data/                 Embedded data (IOCs, popular packages, default policy)
schema/               JSON Schema for output validation
```
