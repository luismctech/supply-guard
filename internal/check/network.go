package check

import (
	"net"
	"regexp"
	"strings"
)

type NetworkIssue struct {
	Pattern  string
	Category string // "download_cmd", "network_api", "raw_ip", "env_exfil", "c2_domain"
	Risk     string // "critical", "high", "medium"
}

var safeRegistries = []string{
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"pypi.org",
	"files.pythonhosted.org",
	"crates.io",
	"api.nuget.org",
	"repo1.maven.org",
	"repo.maven.apache.org",
	"central.sonatype.com",
	"plugins.gradle.org",
	"github.com",
	"raw.githubusercontent.com",
}

var downloadCommands = []string{
	"curl ", "curl\t", "wget ", "wget\t",
	"Invoke-WebRequest", "iwr ",
	"Start-BitsTransfer",
}

var networkAPIs = map[string][]string{
	"npm": {
		"node-fetch", "http.get(", "http.request(",
		"https.get(", "https.request(",
		"axios.get(", "axios.post(",
		"fetch(", "XMLHttpRequest",
		"net.connect(", "net.createConnection(",
		"dgram.createSocket(",
	},
	"pip": {
		"urllib.request", "urllib2.urlopen",
		"requests.get(", "requests.post(",
		"httplib.HTTPConnection", "http.client.HTTPConnection",
		"socket.connect(", "socket.create_connection(",
		"aiohttp.ClientSession",
	},
	"cargo": {
		"reqwest::", "hyper::",
		"std::net::TcpStream",
		"std::net::UdpSocket",
		"tokio::net::",
	},
	"nuget": {
		"HttpClient(", "WebClient(",
		"HttpWebRequest", "WebRequest.Create(",
		"TcpClient(", "Socket(",
	},
	"maven": {
		"URL(", "HttpURLConnection",
		"HttpClient.newHttpClient",
		"OkHttpClient",
	},
}

var execAPIs = map[string][]string{
	"npm": {
		"child_process", "exec(", "execSync(",
		"spawn(", "spawnSync(",
		"eval(", "Function(",
		"Buffer.from(", "atob(", "btoa(",
	},
	"pip": {
		"subprocess.call(", "subprocess.Popen(",
		"subprocess.run(", "os.system(",
		"os.popen(", "exec(", "eval(",
		"compile(", "__import__(",
	},
	"cargo": {
		"std::process::Command",
	},
}

var envExfilPatterns = map[string][]string{
	"npm": {
		"process.env",
	},
	"pip": {
		"os.environ",
	},
	"cargo": {
		"std::env::var",
	},
	"nuget": {
		"Environment.GetEnvironmentVariable",
	},
}

var rawIPRegex = regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}(:\d+)?\b`)

// ScanForNetworkCalls analyzes script content for network-related patterns.
// Returns nil if no suspicious patterns are found.
func ScanForNetworkCalls(content, ecosystem string) []NetworkIssue {
	if content == "" {
		return nil
	}

	var issues []NetworkIssue
	lower := strings.ToLower(content)
	lines := strings.Split(lower, "\n")

	for _, cmd := range downloadCommands {
		lowerCmd := strings.ToLower(cmd)
		for _, line := range lines {
			if strings.Contains(line, lowerCmd) && !lineMentionsSafeRegistry(line) {
				issues = append(issues, NetworkIssue{
					Pattern:  strings.TrimSpace(cmd),
					Category: "download_cmd",
					Risk:     "high",
				})
				break
			}
		}
	}

	if apis, ok := networkAPIs[ecosystem]; ok {
		for _, api := range apis {
			if strings.Contains(content, api) {
				issues = append(issues, NetworkIssue{
					Pattern:  api,
					Category: "network_api",
					Risk:     "high",
				})
			}
		}
	}

	if apis, ok := execAPIs[ecosystem]; ok {
		for _, api := range apis {
			if strings.Contains(content, api) {
				issues = append(issues, NetworkIssue{
					Pattern:  api,
					Category: "exec_api",
					Risk:     "high",
				})
			}
		}
	}

	if rawIPRegex.MatchString(content) {
		ips := rawIPRegex.FindAllString(content, -1)
		for _, ip := range ips {
			if !isLoopback(ip) {
				issues = append(issues, NetworkIssue{
					Pattern:  ip,
					Category: "raw_ip",
					Risk:     "critical",
				})
			}
		}
	}

	if envPats, ok := envExfilPatterns[ecosystem]; ok {
		for _, pat := range envPats {
			if strings.Contains(content, pat) {
				hasNet := false
				for _, issue := range issues {
					if issue.Category == "network_api" || issue.Category == "download_cmd" {
						hasNet = true
						break
					}
				}
				if hasNet {
					issues = append(issues, NetworkIssue{
						Pattern:  pat,
						Category: "env_exfil",
						Risk:     "critical",
					})
				}
			}
		}
	}

	c2Matches, _ := CheckC2Domain(content)
	for _, domain := range c2Matches {
		issues = append(issues, NetworkIssue{
			Pattern:  domain,
			Category: "c2_domain",
			Risk:     "critical",
		})
	}

	return issues
}

func lineMentionsSafeRegistry(line string) bool {
	for _, reg := range safeRegistries {
		if strings.Contains(line, reg) {
			return true
		}
	}
	return false
}

func isLoopback(ip string) bool {
	host := strings.Split(ip, ":")[0]
	parsed := net.ParseIP(host)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsUnspecified() || parsed.IsPrivate()
}
