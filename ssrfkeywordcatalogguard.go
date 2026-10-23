package main

// ssrfkeywordcatalogguard.go —— SSRF 敏感目标关键词目录。
//
// 威胁模型：
//   出向 URL 的主机/路径中出现云元数据、内网管理面、actuator/debug 等关键词需拦截或复核。分词精确匹配，
//   纯字符，不发起连接，不用正则。

// SRF 风险类别。
const (
	SRFClassBlock = "block"
	SRFClassWarn  = "warn"
	SRFClassAllow = "allow"
)

const (
	SRFReasonBlock   = "srf-input-hits-blocked-catalog"
	SRFReasonWarn    = "srf-input-hits-review-catalog"
	SRFReasonPrefix  = "srf-input-hits-dangerous-prefix"
	SRFReasonEmpty   = "srf-input-is-empty"
)

var SRFBlock = []string{
	"metadata",
	"169.254.169.254",
	"169.254.170.2",
	"metadata.google.internal",
	"metadata.aws",
	"latest",
	"meta-data",
	"user-data",
	"iam",
	"security-credentials",
	"dynamic",
	"instance-identity",
	"computeMetadata",
	"actuator",
	"env",
	"heapdump",
	"threaddump",
	"jolokia",
	"debug",
	"debugger",
	"console",
	"admin",
	"manage",
	"management",
	"server-status",
	"server-info",
	"phpinfo",
	"jmxconsole",
	"web-console",
	"hawtio",
	"druid",
	"swagger",
	"swagger-ui",
	"api-docs",
	"graphql",
	"graphiql",
	"playground",
	"internal",
	"intranet",
	"private",
	"docker",
	"kubernetes",
	"k8s",
	"kubelet",
	"kube-apiserver",
	"etcd",
	"consul",
	"zookeeper",
	"nacos",
	"eureka",
	"apollo",
	"configserver",
	"metrics",
	"prometheus",
	"grafana",
	"kibana",
	"jenkins",
	"gitlab",
	"phpmyadmin",
	"adminer",
	"pma",
}

var SRFWarn = []string{
	"localhost",
	"127.0.0.1",
	"0.0.0.0",
	"::1",
	"10.0",
	"192.168",
	"172.16",
	"169.254",
	"100.64",
	"fc00",
	"fe80",
	"gateway",
	"router",
	"proxy",
	"squid",
	"vpn",
	"bastion",
	"jumpbox",
	"loopback",
	"local",
	"cluster",
	"svc",
	"namespace",
	"pod",
	"node",
	"service",
	"registry",
	"status",
	"health",
	"info",
	"trace",
	"traceid",
}

var SRFAllow = []string{
	"api",
	"v1",
	"v2",
	"public",
	"static",
	"assets",
	"cdn",
	"images",
	"img",
	"media",
	"files",
	"download",
	"docs",
	"help",
	"about",
	"contact",
	"search",
	"login",
	"logout",
	"oauth",
	"callback",
	"webhook",
	"events",
	"webhooks",
	"statuspage",
}

var SRFPrefixLit = []string{
}
var SRFPrefixReason = []string{
}

// SRFFinding 表示一条命中。
type SRFFinding struct {
	Reason string
	Detail string
}

// SRFResult 是审计结果。
type SRFResult struct {
	Safe bool
	Findings []SRFFinding
}

func SRFLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func SRFIn(list []string, v string) bool {
	for _, x := range list { if SRFLower(x) == v { return true } }
	return false
}

func SRFSplit(in string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(in); i++ {
		end := i == len(in)
		sep := false
		if !end { c := in[i]; sep = c == ' ' || c == '\t' || c == '\n' || c == '\r' }
		if end || sep {
			if start >= 0 { out = append(out, in[start:i]); start = -1 }
		} else if start < 0 {
			start = i
		}
	}
	return out
}

func SRFKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// SRFHas 判定结果是否含某原因。
func SRFHas(r SRFResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// SRFAudit 审计输入字符串。
func SRFAudit(in string) SRFResult {
	res := SRFResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, SRFFinding{Reason: SRFReasonEmpty}); return res }
	toks := SRFSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := SRFLower(tok)
		key := cmp
		switch {
		case SRFIn(SRFBlock, key):
			res.Findings = append(res.Findings, SRFFinding{Reason: SRFReasonBlock, Detail: key})
		case SRFIn(SRFWarn, key):
			res.Findings = append(res.Findings, SRFFinding{Reason: SRFReasonWarn, Detail: key})
		}
		for i, lit := range SRFPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, SRFFinding{Reason: SRFPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
