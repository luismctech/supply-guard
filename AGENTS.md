# SupplyGuard — Agent Instructions

SupplyGuard is an offline supply-chain security scanner for npm, pip, Cargo, Maven, and NuGet.
It detects malicious packages, typosquatting, phantom dependencies, IOC matches, and policy violations.

## Commands

| Command | Purpose |
|---------|---------|
| `supply-guard scan [dir]` | Scan a project for supply chain threats |
| `supply-guard report <file.json>` | Generate formatted reports from saved scan results |
| `supply-guard mcp` | Start MCP server over stdio for AI agent integration |
| `supply-guard init [dir]` | Scaffold `supplyguard.yaml` and `.npmrc` hardening config |
| `supply-guard update` | Download the latest IOC threat intelligence database |
| `supply-guard version` | Print version and build information |

## Scan Command

```bash
# Scan current directory (human-readable table)
supply-guard scan

# JSON output (best for programmatic parsing)
supply-guard scan --output json --quiet

# Markdown output (best for chat display and PR comments)
supply-guard scan --output markdown --quiet

# Unified diff patches (pipe to git apply for auto-fixing)
supply-guard scan --output diff --quiet

# SARIF output (for GitHub Code Scanning / VS Code)
supply-guard scan --output sarif --quiet

# Stream-JSON (NDJSON events for real-time processing)
supply-guard scan --output stream-json --quiet

# Scan specific directory
supply-guard scan /path/to/project --output json -q

# Fail on critical/high findings (CI mode)
supply-guard scan --fail-on critical,high --output json -q

# Show only new findings vs. a baseline
supply-guard scan --baseline baseline.json --output json -q

# Watch mode (re-scans when dependency files change)
supply-guard scan --watch
```

### Scan flags

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output format: table, json, sarif, markdown, diff, stream-json |
| `--quiet` | `-q` | Suppress banners, warnings, and decorations |
| `--fail-on` | | Fail with exit 1 on these severities (e.g. `critical,high`) |
| `--baseline` | | Path to previous scan JSON for diffing (only new findings) |
| `--watch` | | Watch for file changes and re-scan continuously |
| `--config` | | Path to a trusted config file |

## Report Command

Generate formatted reports from a saved JSON scan result:

```bash
# Save a scan first
supply-guard scan --output json --quiet > scan-result.json

# GitHub PR comment with collapsible severity sections
supply-guard report scan-result.json -f pr-comment

# Executive summary for stakeholders
supply-guard report scan-result.json -f executive-summary

# Git commit message for security fix commits
supply-guard report scan-result.json -f commit-message

# Developer-focused action items list
supply-guard report scan-result.json -f developer-brief
```

## Output Formats

| Format | Flag | Best for |
|--------|------|----------|
| `table` | `--output table` | Human terminal display (default) |
| `json` | `--output json` | Programmatic parsing, automation |
| `sarif` | `--output sarif` | GitHub Code Scanning, IDE integration |
| `markdown` | `--output markdown` | AI chat display, PR comments |
| `diff` | `--output diff` | Auto-applying fixes via `git apply` |
| `stream-json` | `--output stream-json` | Real-time NDJSON event streaming |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings above threshold |
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
- `file`, `line`: exact location in the codebase
- `fingerprint`: stable SHA-256 prefix for deduplication across scans
- `fix`: machine-actionable fix suggestion (when available)
  - `fix.type`: replace, delete, add, config_change, command
  - `fix.old_content`, `fix.new_content`: for deterministic fixes
  - `fix.description`: for fixes requiring judgment

## MCP Server

SupplyGuard exposes an MCP server for direct tool integration with AI agents.

### Configuration

Add to your MCP configuration:

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

### Available Tools

**`scan`** — Scan a directory for supply chain threats.

```json
{ "directory": ".", "checks": ["SG001", "SG006"], "format": "json" }
```

All parameters are optional. Omit `checks` to run all checks. `format` defaults to `json`.

**`explain_finding`** — Get a detailed explanation of a check with real-world attack examples.

```json
{ "check_id": "SG006", "package": "lod4sh" }
```

Returns markdown with Risk, Attack Vector, Impact, and Real-World Examples sections.

**`suggest_fix`** — Get step-by-step remediation for a finding.

```json
{ "check_id": "SG009", "file": ".github/workflows/ci.yml", "ecosystem": "ci" }
```

Returns markdown with concrete fix instructions, code examples, and config snippets.

**`list_checks`** — List all 12 security checks with descriptions and ecosystems.

```json
{}
```

**`get_policy`** — Read the active SupplyGuard policy configuration.

```json
{}
```

### Available Resources

| URI | Description |
|-----|-------------|
| `supplyguard://checks` | All check IDs with descriptions (JSON) |
| `supplyguard://policy/{dir}` | Active policy for a directory (JSON) |

## Agent Workflows

### Workflow 1: Scan and filter critical/high findings

```bash
supply-guard scan --output json -q | jq '.findings[] | select(.severity == "critical" or .severity == "high")'
```

### Workflow 2: Auto-fix all fixable findings

```bash
supply-guard scan --output diff -q > fixes.patch
git apply fixes.patch
```

### Workflow 3: Baseline diffing (only new findings)

```bash
supply-guard scan --output json -q > baseline.json
# ... make changes ...
supply-guard scan --baseline baseline.json --output json -q
```

### Workflow 4: Generate a PR comment

```bash
supply-guard scan --output json -q > scan-result.json
supply-guard report scan-result.json -f pr-comment
```

### Workflow 5: Generate a commit message after fixing

```bash
supply-guard report scan-result.json -f commit-message
```

## Check IDs

| ID | Description | Ecosystems |
|----|-------------|------------|
| SG001 | Lockfile integrity verification | npm, pip, cargo |
| SG002 | Install script detection | npm, pip, cargo |
| SG003 | Known malicious package/domain match (IOC) | all |
| SG004 | Dependency age check | npm |
| SG005 | Phantom dependency detection | npm |
| SG006 | Typosquatting detection | all |
| SG007 | Provenance verification | all, ci |
| SG008 | Package manager config hardening | npm, pip |
| SG009 | GitHub Actions SHA pinning | ci |
| SG010 | Network call detection in scripts | all |
| SG011 | Version range permissiveness | all |
| SG012 | Unsafe CI install commands | ci |

## Project Layout

```
cmd/supply-guard/        Entry point (main.go)
internal/
  analyzer/              Per-ecosystem analyzers (npm, pip, cargo, maven, nuget)
  check/                 Shared check logic (IOC, typosquat, provenance, etc.)
  cmd/                   CLI commands (scan, init, update, version, mcp, report)
  config/                Configuration loading (supplyguard.yaml)
  engine/                Scan orchestrator
  mcp/                   MCP server (protocol, tools, resources, explanations)
  policy/                Policy engine (rules, severity overrides)
  report/                Output formatters (table, json, sarif, markdown, diff, stream)
  safefile/              Safe file I/O (symlink protection, size limits)
  types/                 Core types (Finding, ScanResult, FixSuggestion, Severity)
data/                    Embedded data (IOCs, popular packages, default policy)
schema/                  JSON Schema for output validation
```
