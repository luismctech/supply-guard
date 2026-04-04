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
supply-guard scan -o json -q

# SARIF output for GitHub Code Scanning / VS Code
supply-guard scan -o sarif

# Markdown output for PR comments and AI chat
supply-guard scan -o markdown -q

# Auto-fix patches (pipe to git apply)
supply-guard scan -o diff -q > fixes.patch && git apply fixes.patch

# Fail CI on critical or high findings
supply-guard scan --fail-on critical,high

# Only show new findings vs. a baseline
supply-guard scan -o json -q > baseline.json
# ... later ...
supply-guard scan --baseline baseline.json -o json -q

# Watch mode (re-scans on file changes)
supply-guard scan --watch

# Initialize hardening config in your project
supply-guard init

# Install AI agent integration files (Cursor rules, MCP configs, AGENTS.md, SKILL.md)
supply-guard agents install

# Install only Cursor-specific files
supply-guard agents install --cursor

# Check which agent files are installed
supply-guard agents list

# Generate a PR comment from a saved scan
supply-guard report scan-result.json -f pr-comment
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

## AI/Agent integration

SupplyGuard is designed to be first-class AI-agent friendly. It can be used by any AI coding assistant via CLI, MCP server, or agent guidance files.

### Quick setup

Install all agent integration files into your project with a single command:

```bash
supply-guard agents install
```

This creates:

| File | Purpose |
|------|---------|
| `.cursor/rules/supply-guard.mdc` | Auto-triggers scanning on dependency file edits |
| `.cursor/mcp.json` | Registers SupplyGuard as MCP server in Cursor |
| `.vscode/mcp.json` | Registers SupplyGuard as MCP server in VS Code / Copilot |
| `AGENTS.md` | Agent instructions for Codex and GitHub Copilot |
| `SKILL.md` | Cursor skill definition |

Select specific integrations with flags:

```bash
supply-guard agents install --cursor   # Cursor rule + MCP config + SKILL.md
supply-guard agents install --vscode   # VS Code MCP config
supply-guard agents install --docs     # AGENTS.md + SKILL.md
```

MCP configs are merged non-destructively: existing servers in `.cursor/mcp.json` or `.vscode/mcp.json` are preserved.

Check install status with `supply-guard agents list`.

### MCP Server

The `supply-guard mcp` command starts a [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio, allowing AI agents to call SupplyGuard as typed tools without parsing CLI output.

#### Setup in Cursor

Add to your MCP configuration (`.cursor/mcp.json` or Settings > MCP Servers):

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

#### Setup in VS Code / GitHub Copilot

Add to `.vscode/mcp.json` in your project:

```json
{
  "servers": {
    "supply-guard": {
      "type": "stdio",
      "command": "supply-guard",
      "args": ["mcp"]
    }
  }
}
```

#### Setup in Claude Desktop

Add to `claude_desktop_config.json`:

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

> **Prerequisite:** The `supply-guard` binary must be installed and available in your PATH. See [Installation](#installation).

#### MCP tools

Once configured, the following tools are available to your AI agent:

| Tool | Description | Example usage |
|------|-------------|---------------|
| `scan` | Run a full or targeted scan on a directory | `scan({ directory: ".", format: "markdown" })` |
| `explain_finding` | Deep-dive on why a check matters, with real-world attack examples | `explain_finding({ check_id: "SG006", package: "lod4sh" })` |
| `suggest_fix` | Step-by-step remediation instructions for a finding | `suggest_fix({ check_id: "SG009", file: ".github/workflows/ci.yml" })` |
| `list_checks` | List all 12 security checks with descriptions and ecosystems | `list_checks({})` |
| `get_policy` | Read the active SupplyGuard policy configuration | `get_policy({})` |
| `install_agent_files` | Install agent integration files into a project | `install_agent_files({ directory: ".", files: ["cursor-rule"] })` |

#### MCP resources

| Resource URI | Description |
|---|---|
| `supplyguard://checks` | All check IDs with descriptions (JSON) |
| `supplyguard://policy/{dir}` | Active policy configuration for a directory (JSON) |

### Report command

Generate formatted reports from a saved JSON scan result:

```bash
# Save scan results
supply-guard scan -o json -q > scan-result.json

# GitHub PR comment (collapsible sections by severity)
supply-guard report scan-result.json -f pr-comment

# Executive summary for stakeholders
supply-guard report scan-result.json -f executive-summary

# Git commit message for security fixes
supply-guard report scan-result.json -f commit-message

# Developer action items
supply-guard report scan-result.json -f developer-brief
```

### Output formats

| Format | Flag | Best for |
|--------|------|----------|
| `table` | `-o table` | Human terminal display (default) |
| `json` | `-o json` | Programmatic parsing, automation |
| `sarif` | `-o sarif` | GitHub Code Scanning, IDE integration |
| `markdown` | `-o markdown` | AI chat display, PR comments |
| `diff` | `-o diff` | Auto-applying fixes via `git apply` |
| `stream-json` | `-o stream-json` | Real-time NDJSON event streaming |

### CLI flags reference

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output format (table, json, sarif, markdown, diff, stream-json) |
| `--quiet` | `-q` | Suppress banners, warnings, and decorations |
| `--fail-on` | | Fail with exit 1 on these severities (e.g. `critical,high`) |
| `--baseline` | | Path to previous scan JSON, shows only new findings |
| `--watch` | | Watch for file changes and re-scan continuously |
| `--config` | | Path to trusted config file |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Findings exceed `--fail-on` severity threshold |
| 2 | Scanner error (bad config, invalid path, etc.) |
| 10 | Critical findings present |
| 11 | High findings present (no critical) |
| 12 | Medium findings present (no critical/high) |

### Fix suggestions

Every finding includes a machine-actionable `fix` field (when available) with:

- `type` — `replace`, `delete`, `add`, `config_change`, or `command`
- `file`, `line` — target location
- `old_content`, `new_content` — for deterministic text replacements
- `description` — human-readable instructions when the fix requires judgment

Use `--output diff` to generate `git apply`-compatible patches from all fixable findings.

### Baseline diffing

Compare scans across time using stable fingerprints:

```bash
# Initial scan
supply-guard scan -o json -q > baseline.json

# After changes, show only NEW findings
supply-guard scan --baseline baseline.json -o json -q
```

Each finding has a `fingerprint` field (SHA-256 prefix of check_id + file + package + version) for deduplication.

### Agent guidance files

SupplyGuard ships files that AI agents auto-discover:

| File | Auto-discovered by | Purpose |
|------|-------------------|---------|
| `AGENTS.md` | OpenAI Codex, GitHub Copilot | CLI reference, workflows, project layout |
| `SKILL.md` | Cursor Skills | When to use, how to invoke, how to interpret results |
| `.cursor/rules/supply-guard.mdc` | Cursor | Auto-triggers when editing dependency files |
| `schema/scan-result.schema.json` | Any JSON-aware agent | Formal schema for validating JSON output |

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
