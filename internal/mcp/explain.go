package mcp

import (
	"fmt"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

var checkExplanations = map[types.CheckID]struct {
	Risk     string
	Attack   string
	Impact   string
	Examples []string
}{
	types.CheckLockfileIntegrity: {
		Risk:   "A missing or outdated lockfile allows supply chain attacks where a malicious package version is silently installed during CI/CD.",
		Attack: "An attacker publishes a compromised version of a popular package. Without a lockfile, `npm install` or `pip install` resolves to the latest (malicious) version.",
		Impact: "Remote code execution during install, data exfiltration, cryptocurrency mining, backdoors in production builds.",
		Examples: []string{
			"ua-parser-js (2021): Compromised versions 0.7.29/0.8.0/1.0.0 installed cryptominers",
			"event-stream (2018): Malicious version targeted a specific cryptocurrency wallet",
		},
	},
	types.CheckInstallScripts: {
		Risk:   "Install scripts (preinstall, postinstall) execute arbitrary code during `npm install` with the developer's full permissions.",
		Attack: "A malicious package or compromised maintainer account adds a postinstall script that exfiltrates environment variables, SSH keys, or installs a backdoor.",
		Impact: "Immediate code execution on developer machines and CI/CD servers. Full access to file system, network, and credentials.",
		Examples: []string{
			"eslint-scope (2018): Stolen npm token used to publish versions with credential-stealing postinstall scripts",
			"ua-parser-js (2021): Postinstall script deployed platform-specific cryptominers",
		},
	},
	types.CheckIOCMatch: {
		Risk:   "The package or domain matches known Indicators of Compromise from threat intelligence databases.",
		Attack: "Known malicious packages are published to registries mimicking legitimate software. C2 (Command & Control) domains embedded in scripts phone home to attacker infrastructure.",
		Impact: "Active compromise. The package is confirmed malicious and should be removed immediately.",
		Examples: []string{
			"colors/faker (2022): Maintainer sabotaged packages affecting thousands of projects",
			"node-ipc (2022): Maintainer added code targeting Russian/Belarusian IP addresses",
		},
	},
	types.CheckDependencyAge: {
		Risk:   "Dependencies published in the last 7 days haven't been community-vetted and may contain undiscovered malicious code.",
		Attack: "Attackers publish malicious packages and rely on rapid adoption before detection. Star-jacking and social engineering accelerate trust.",
		Impact: "Early exposure to supply chain attacks before the community identifies and reports the threat.",
	},
	types.CheckPhantomDependency: {
		Risk:   "Code imports a package that isn't declared in package.json, relying on transitive installation that may change or disappear.",
		Attack: "An attacker registers the undeclared package name on npm. When the transitive dependency tree changes, the malicious package is installed instead.",
		Impact: "Arbitrary code execution via a package the developer never explicitly chose to trust.",
	},
	types.CheckTyposquatting: {
		Risk:   "A package name closely resembles a popular package, suggesting possible typosquatting.",
		Attack: "Attackers register packages with names similar to popular ones (e.g., `lod4sh` instead of `lodash`). Developers who mistype package names install the malicious version.",
		Impact: "Code execution, credential theft, or backdoor installation through a package the developer intended to be something else.",
		Examples: []string{
			"crossenv (2017): Typosquat of cross-env that stole environment variables",
			"colourama (2018): Typosquat of colorama (Python) that installed a backdoor",
		},
	},
	types.CheckProvenance: {
		Risk:   "Missing integrity hashes or provenance attestations mean you cannot verify that installed packages match what was published.",
		Attack: "Man-in-the-middle attacks or registry compromises can substitute packages. Without hash verification, tampered packages install silently.",
		Impact: "Undetectable package substitution. SLSA Level 0 means no supply chain security guarantees.",
	},
	types.CheckConfigHardening: {
		Risk:   "Package manager defaults allow dangerous behaviors like automatic script execution and unverified downloads.",
		Attack: "Without `ignore-scripts=true` in .npmrc, every `npm install` executes preinstall/postinstall scripts from all dependencies automatically.",
		Impact: "Expanded attack surface for all dependency-related attacks.",
	},
	types.CheckActionsPinning: {
		Risk:   "GitHub Actions referenced by tag (e.g., `@v3`) can be silently replaced with malicious code by the action maintainer or a compromised account.",
		Attack: "The GhostActions campaign (2023) compromised 327 repositories by manipulating mutable tags on popular actions. The tag points to new, malicious code.",
		Impact: "CI/CD pipeline compromise. Secrets exfiltration, artifact tampering, supply chain poisoning of downstream consumers.",
		Examples: []string{
			"tj-actions/changed-files (2025): Compromised action injected secrets-dumping code affecting 23,000+ repos",
		},
	},
	types.CheckNetworkCalls: {
		Risk:   "Build or install scripts contain network calls, command execution APIs, or environment variable exfiltration patterns.",
		Attack: "Malicious packages use curl/wget in install scripts to download second-stage payloads, or use exec() to run arbitrary commands. Environment variables containing secrets are sent to attacker servers.",
		Impact: "Data exfiltration, remote code execution, credential theft during build/install phase.",
	},
	types.CheckVersionRange: {
		Risk:   "Overly permissive version ranges (*, >=, ^) allow automatic upgrades to potentially compromised versions.",
		Attack: "An attacker compromises a maintainer account and publishes a malicious patch/minor version. All projects using permissive ranges automatically install the compromised version.",
		Impact: "Silent adoption of malicious code through normal dependency resolution.",
	},
	types.CheckCIInstall: {
		Risk:   "CI workflows use unsafe install patterns like `curl | sh`, `pip install` without hashes, or `npm install` instead of `npm ci`.",
		Attack: "Unsanitized install commands in CI can fetch different code than what was tested, bypassing lockfile protections.",
		Impact: "CI/CD pipeline compromise through dependency confusion, DNS hijacking, or registry compromise.",
	},
}

func explainCheck(checkID types.CheckID, description, pkg string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# %s: %s\n\n", checkID, description)

	info, ok := checkExplanations[checkID]
	if !ok {
		fmt.Fprintf(&sb, "No detailed explanation available for this check.\n")
		return sb.String()
	}

	fmt.Fprintf(&sb, "## Risk\n\n%s\n\n", info.Risk)
	fmt.Fprintf(&sb, "## Attack Vector\n\n%s\n\n", info.Attack)
	fmt.Fprintf(&sb, "## Impact\n\n%s\n\n", info.Impact)

	if len(info.Examples) > 0 {
		fmt.Fprintf(&sb, "## Real-World Examples\n\n")
		for _, ex := range info.Examples {
			fmt.Fprintf(&sb, "- %s\n", ex)
		}
		fmt.Fprintf(&sb, "\n")
	}

	if pkg != "" {
		fmt.Fprintf(&sb, "## Context\n\nThis finding relates to package `%s`.\n", pkg)
	}

	return sb.String()
}

func suggestFixForCheck(checkID types.CheckID, file, pkg, ecosystem string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Fix for %s\n\n", checkID)

	switch checkID {
	case types.CheckLockfileIntegrity:
		sb.WriteString("## Steps\n\n")
		sb.WriteString("1. Regenerate the lockfile:\n")
		sb.WriteString("   - npm: `npm install` (creates/updates package-lock.json)\n")
		sb.WriteString("   - pip: `pip freeze > requirements.txt`\n")
		sb.WriteString("   - cargo: `cargo generate-lockfile`\n")
		sb.WriteString("2. Commit the lockfile to version control\n")
		sb.WriteString("3. Use `npm ci` (not `npm install`) in CI pipelines\n")

	case types.CheckInstallScripts:
		fmt.Fprintf(&sb, "## For package `%s`\n\n", pkg)
		sb.WriteString("1. Review the install scripts to verify they are safe\n")
		sb.WriteString("2. If safe, add to `supplyguard.yaml`:\n\n")
		fmt.Fprintf(&sb, "```yaml\nignore_rules:\n  - check: SG002\n    package: \"%s\"\n    reason: \"Reviewed and approved\"\n```\n\n", pkg)
		sb.WriteString("3. If unsafe, replace the package with a safer alternative\n")

	case types.CheckActionsPinning:
		fmt.Fprintf(&sb, "## Pin action in `%s`\n\n", file)
		sb.WriteString("1. Find the action's repository on GitHub\n")
		sb.WriteString("2. Go to Releases or Tags\n")
		sb.WriteString("3. Click the commit SHA for the desired version\n")
		sb.WriteString("4. Replace the tag reference with the full SHA:\n\n")
		sb.WriteString("```yaml\n# Before (unsafe)\n- uses: actions/checkout@v4\n\n# After (safe)\n- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n```\n")

	case types.CheckTyposquatting:
		fmt.Fprintf(&sb, "## Verify package `%s`\n\n", pkg)
		sb.WriteString("1. Check if this is the intended package name\n")
		sb.WriteString("2. Verify on the package registry (npmjs.com, pypi.org, crates.io)\n")
		sb.WriteString("3. If typosquatting: remove and install the correct package\n")
		sb.WriteString("4. If legitimate: suppress with:\n\n")
		fmt.Fprintf(&sb, "```yaml\nignore_rules:\n  - check: SG006\n    package: \"%s\"\n    reason: \"Verified as legitimate\"\n```\n", pkg)

	case types.CheckConfigHardening:
		sb.WriteString("## Harden package manager configuration\n\n")
		switch ecosystem {
		case "npm":
			sb.WriteString("Create or update `.npmrc`:\n\n")
			sb.WriteString("```ini\nignore-scripts=true\naudit=true\nengine-strict=true\n```\n")
		case "pip":
			sb.WriteString("Use requirements with hashes:\n\n")
			sb.WriteString("```bash\npip install --require-hashes -r requirements.txt\n```\n")
		default:
			sb.WriteString("Configure your package manager with security-hardened defaults.\n")
		}

	case types.CheckVersionRange:
		fmt.Fprintf(&sb, "## Pin `%s` to exact version\n\n", pkg)
		sb.WriteString("1. Find the currently installed version in your lockfile\n")
		sb.WriteString("2. Replace the range with the exact version:\n\n")
		sb.WriteString("```json\n// Before\n\"lodash\": \"^4.17.0\"\n\n// After\n\"lodash\": \"4.17.21\"\n```\n")

	case types.CheckPhantomDependency:
		fmt.Fprintf(&sb, "## Add `%s` as explicit dependency\n\n", pkg)
		sb.WriteString("```bash\nnpm install " + pkg + " --save\n```\n\n")
		sb.WriteString("This ensures the package version is tracked and locked.\n")

	case types.CheckCIInstall:
		fmt.Fprintf(&sb, "## Fix CI install in `%s`\n\n", file)
		sb.WriteString("Replace unsafe install patterns:\n\n")
		sb.WriteString("```yaml\n# Before (unsafe)\nrun: curl -sS https://example.com/install.sh | sh\n\n")
		sb.WriteString("# After (safe)\nrun: |\n  curl -sS -o install.sh https://example.com/install.sh\n  sha256sum -c <<< 'EXPECTED_HASH  install.sh'\n  sh install.sh\n```\n\n")
		sb.WriteString("Or use lockfile-based installs:\n")
		sb.WriteString("- npm: `npm ci` instead of `npm install`\n")
		sb.WriteString("- pip: `pip install -r requirements.txt --require-hashes`\n")

	default:
		sb.WriteString("Review the finding details and apply the suggested remediation.\n")
	}

	return sb.String()
}
