package main

// reservednetdirectoryguard.go —— 保留/私有/元数据网络地址目录。
//
// 威胁模型：
//   SSRF 出向目标需识别环回/链路本地/RFC1918/ULA/云元数据端点等敏感地址，避免把远端 URL 指向内部服务。
//   本目录登记地址与元数据主机令牌，纯字符查表，不发起连接，不用正则。

// RND 风险类别。
const (
	RNDClassBlock = "block"
	RNDClassWarn  = "warn"
	RNDClassAllow = "allow"
)

const (
	RNDReasonBlock   = "rnd-input-hits-blocked-catalog"
	RNDReasonWarn    = "rnd-input-hits-review-catalog"
	RNDReasonPrefix  = "rnd-input-hits-dangerous-prefix"
	RNDReasonEmpty   = "rnd-input-is-empty"
)

var RNDBlock = []string{
	"127.0.0.1",
	"127.0.0.2",
	"127.255.255.254",
	"::1",
	"0:0:0:0:0:0:0:1",
	"0:0:0:0:0:0:0:0",
	"::",
	"0.0.0.0",
	"0000:0000:0000:0000:0000:0000:0000:0001",
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"169.254.169.254",
	"169.254.170.2",
	"fd00:ec2::254",
	"metadata.google.internal",
	"metadata",
	"metadata.azure.com",
	"169.254.169.253",
	"metadata.packet.net",
	"100.100.100.200",
}

var RNDWarn = []string{
	"10.0.0.0",
	"10.255.255.255",
	"172.16.0.0",
	"172.31.255.255",
	"192.168.0.0",
	"192.168.255.255",
	"100.64.0.0",
	"100.127.255.255",
	"169.254.0.0",
	"169.254.255.255",
	"fc00::",
	"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	"fe80::",
	"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	"192.0.2.0",
	"198.51.100.0",
	"203.0.113.0",
	"::ffff:127.0.0.1",
	"::ffff:10.0.0.1",
	"::ffff:192.168.0.1",
	"0.0.0.0/8",
	"240.0.0.0",
	"255.255.255.255",
	"224.0.0.0",
	"internal",
	"internal.cloudapp.net",
	"cluster.local",
	"kubernetes.default.svc",
	"kubernetes",
	"docker.internal",
	"host.docker.internal",
	"gateway.docker.internal",
	"k3d-k3s-default-serverlb",
	"minikube.internal",
	"host.containers.internal",
}

var RNDAllow = []string{
	"8.8.8.8",
	"8.8.4.4",
	"1.1.1.1",
	"1.0.0.1",
	"9.9.9.9",
	"149.112.112.112",
	"208.67.222.222",
	"208.67.220.220",
	"2606:4700:4700::1111",
	"2001:4860:4860::8888",
	"2001:4860:4860::8844",
	"example.com",
	"example.org",
	"example.net",
	"www.example.com",
}

var RNDPrefixLit = []string{
}
var RNDPrefixReason = []string{
}

// RNDFinding 表示一条命中。
type RNDFinding struct {
	Reason string
	Detail string
}

// RNDResult 是审计结果。
type RNDResult struct {
	Safe bool
	Findings []RNDFinding
}

func RNDLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func RNDIn(list []string, v string) bool {
	for _, x := range list { if RNDLower(x) == v { return true } }
	return false
}

func RNDSplit(in string) []string {
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

func RNDKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// RNDHas 判定结果是否含某原因。
func RNDHas(r RNDResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// RNDAudit 审计输入字符串。
func RNDAudit(in string) RNDResult {
	res := RNDResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, RNDFinding{Reason: RNDReasonEmpty}); return res }
	toks := RNDSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := RNDLower(tok)
		key := cmp
		switch {
		case RNDIn(RNDBlock, key):
			res.Findings = append(res.Findings, RNDFinding{Reason: RNDReasonBlock, Detail: key})
		case RNDIn(RNDWarn, key):
			res.Findings = append(res.Findings, RNDFinding{Reason: RNDReasonWarn, Detail: key})
		}
		for i, lit := range RNDPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, RNDFinding{Reason: RNDPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
