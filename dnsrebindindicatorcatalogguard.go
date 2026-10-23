package main

// dnsrebindindicatorcatalogguard.go —— DNS Rebinding/内网指标目录。
//
// 威胁模型：
//   nip.io/sslip.io 等泛解析域名、169.254.169.254 云元数据地址、0.0.0.0 是 SSRF/DNS rebinding 指标，出向连接需阻断。纯字符查表，不用正则。

const (
	DNIClassBlock   = "block"
	DNIClassWarn    = "warn"
	DNIClassAllow   = "allow"
	DNIClassUnknown = "unknown"
)

var DNIBlock = []string{
	"rebind",
	"nip.io",
	"sslip.io",
	"xip.io",
	"localtest.me",
	"169.254.169.254",
	"metadata.google.internal",
	"0.0.0.0",
}

var DNIWarn = []string{
	"localhost",
	"local",
	"internal",
	"metadata",
	"127.0.0.1",
	"::1",
	"10.0.0.0",
	"192.168.0.0",
	"172.16.0.0",
	"cluster.local",
	"svc.cluster.local",
	"docker.internal",
	"host.docker.internal",
}

var DNIAllow = []string{
	"example.com",
	"example.org",
	"example.net",
	"test.invalid",
}

func DNILower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func DNIIn(list []string, v string) bool {
	for _, x := range list { if DNILower(x) == v { return true } }
	return false
}

// DNIClassify 分类单个令牌。
func DNIClassify(tok string) string {
	v := DNILower(tok)
	switch {
	case DNIIn(DNIBlock, v): return DNIClassBlock
	case DNIIn(DNIWarn, v): return DNIClassWarn
	case DNIIn(DNIAllow, v): return DNIClassAllow
	default: return DNIClassUnknown
	}
}
