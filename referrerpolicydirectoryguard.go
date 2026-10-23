package main

// referrerpolicydirectoryguard.go —— Referrer-Policy 取值目录。
//
// 威胁模型：
//   unsafe-url 与空策略会把完整 URL（含令牌/路径参数）泄露给第三方，
//   跨站导航应降级或不发送来源。纯字符查表，不用正则。

const (
	RFPClassBlock   = "block"
	RFPClassWarn    = "warn"
	RFPClassAllow   = "allow"
	RFPClassUnknown = "unknown"
)

var RFPBlock = []string{
	"unsafe-url",
	"",
	"no-referrer-when-downgrade",
}

var RFPWarn = []string{
	"origin-when-cross-origin",
	"strict-origin-when-cross-origin",
	"origin",
}

var RFPAllow = []string{
	"no-referrer",
	"same-origin",
}

func RFPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func RFPIn(list []string, v string) bool {
	for _, x := range list { if RFPLower(x) == v { return true } }
	return false
}

// RFPClassify 分类单个令牌。
func RFPClassify(tok string) string {
	v := RFPLower(tok)
	switch {
	case RFPIn(RFPBlock, v): return RFPClassBlock
	case RFPIn(RFPWarn, v): return RFPClassWarn
	case RFPIn(RFPAllow, v): return RFPClassAllow
	default: return RFPClassUnknown
	}
}
