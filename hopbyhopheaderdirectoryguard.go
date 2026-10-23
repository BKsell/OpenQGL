package main

// hopbyhopheaderdirectoryguard.go —— 逐跳(Hop-by-Hop)头目录。
//
// 威胁模型：
//   Connection/TE/Trailer/Proxy-* 等逐跳头会被代理删除，攻击者注入可走私或绕过外层策略，
//   转发前必须剥离，不允许来自客户端。纯字符查表，不用正则。

const (
	HHHClassBlock   = "block"
	HHHClassWarn    = "warn"
	HHHClassAllow   = "allow"
	HHHClassUnknown = "unknown"
)

var HHHBlock = []string{
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
}

var HHHWarn = []string{
	"via",
	"x-forwarded-host",
	"x-forwarded-proto",
}

var HHHAllow = []string{
	"accept-encoding",
	"content-type",
	"vary",
}

func HHHLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func HHHIn(list []string, v string) bool {
	for _, x := range list { if HHHLower(x) == v { return true } }
	return false
}

// HHHClassify 分类单个令牌。
func HHHClassify(tok string) string {
	v := HHHLower(tok)
	switch {
	case HHHIn(HHHBlock, v): return HHHClassBlock
	case HHHIn(HHHWarn, v): return HHHClassWarn
	case HHHIn(HHHAllow, v): return HHHClassAllow
	default: return HHHClassUnknown
	}
}
