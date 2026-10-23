package main

// xframeoptiondirectoryguard.go —— X-Frame-Options 取值目录。
//
// 威胁模型：
//   ALLOWALL 等于允许任意站点框架嵌套导致点击劫持，
//   应 DENY 或 SAMEORIGIN，或改用 CSP frame-ancestors。纯字符查表，不用正则。

const (
	XFOClassBlock   = "block"
	XFOClassWarn    = "warn"
	XFOClassAllow   = "allow"
	XFOClassUnknown = "unknown"
)

var XFOBlock = []string{
	"allowall",
	"",
}

var XFOWarn = []string{
	"sameorigin",
}

var XFOAllow = []string{
	"deny",
	"frame-ancestors",
}

func XFOLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func XFOIn(list []string, v string) bool {
	for _, x := range list { if XFOLower(x) == v { return true } }
	return false
}

// XFOClassify 分类单个令牌。
func XFOClassify(tok string) string {
	v := XFOLower(tok)
	switch {
	case XFOIn(XFOBlock, v): return XFOClassBlock
	case XFOIn(XFOWarn, v): return XFOClassWarn
	case XFOIn(XFOAllow, v): return XFOClassAllow
	default: return XFOClassUnknown
	}
}
