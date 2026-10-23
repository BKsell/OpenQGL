package main

// ratelimitenforcementdirectoryguard.go —— 限流缺失/响应目录。
//
// 威胁模型：
//   认证/敏感接口无限流、缺 Retry-After 可被爆破与撞库，
//   应有限流并在 429 回退。纯字符查表，不用正则。

const (
	RTHClassBlock   = "block"
	RTHClassWarn    = "warn"
	RTHClassAllow   = "allow"
	RTHClassUnknown = "unknown"
)

var RTHBlock = []string{
	"no-limit",
	"no-429",
	"auth-unthrottled",
}

var RTHWarn = []string{
	"fixed-window",
}

var RTHAllow = []string{
	"429",
	"retry-after",
}

func RTHLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func RTHIn(list []string, v string) bool {
	for _, x := range list { if RTHLower(x) == v { return true } }
	return false
}

// RTHClassify 分类单个令牌。
func RTHClassify(tok string) string {
	v := RTHLower(tok)
	switch {
	case RTHIn(RTHBlock, v): return RTHClassBlock
	case RTHIn(RTHWarn, v): return RTHClassWarn
	case RTHIn(RTHAllow, v): return RTHClassAllow
	default: return RTHClassUnknown
	}
}
