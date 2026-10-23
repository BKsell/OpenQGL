package main

// androidcleartexttrafficdirectoryguard.go —— Android 明文流量配置目录。
//
// 威胁模型：
//   usesCleartextTraffic=true 或 networkSecurityConfig 放行 cleartext 使 HTTP 可被劫持，
//   应仅允许 https。纯字符查表，不用正则。

const (
	ACTClassBlock   = "block"
	ACTClassWarn    = "warn"
	ACTClassAllow   = "allow"
	ACTClassUnknown = "unknown"
)

var ACTBlock = []string{
	"usescleartexttraffic-true",
	"cleartexttrafficpermitted",
	"cleartext-config",
}

var ACTWarn = []string{
	"http-domain-exception",
}

var ACTAllow = []string{
	"https-only",
}

func ACTLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func ACTIn(list []string, v string) bool {
	for _, x := range list { if ACTLower(x) == v { return true } }
	return false
}

// ACTClassify 分类单个令牌。
func ACTClassify(tok string) string {
	v := ACTLower(tok)
	switch {
	case ACTIn(ACTBlock, v): return ACTClassBlock
	case ACTIn(ACTWarn, v): return ACTClassWarn
	case ACTIn(ACTAllow, v): return ACTClassAllow
	default: return ACTClassUnknown
	}
}
