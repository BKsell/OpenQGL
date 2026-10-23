package main

// unicodedomainconfusabledirectoryguard.go —— 同形混淆/不可见字符目录。
//
// 威胁模型：
//   xn-- 同形域、RTL 覆盖 U+202E、零宽字符、全角字符可做钓鱼域，
//   展示与校验前要规范化并提示 punycode。纯字符查表，不用正则。

const (
	UDCClassBlock   = "block"
	UDCClassWarn    = "warn"
	UDCClassAllow   = "allow"
	UDCClassUnknown = "unknown"
)

var UDCBlock = []string{
	"xn--",
	"u+202e",
	"u+200b",
	"u+200c",
	"u+200d",
	"u+feff",
	"fullwidth",
}

var UDCWarn = []string{
	"u+0301",
	"combining",
}

var UDCAllow = []string{
	"ascii-label",
	"punycode-shown",
}

func UDCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func UDCIn(list []string, v string) bool {
	for _, x := range list { if UDCLower(x) == v { return true } }
	return false
}

// UDCClassify 分类单个令牌。
func UDCClassify(tok string) string {
	v := UDCLower(tok)
	switch {
	case UDCIn(UDCBlock, v): return UDCClassBlock
	case UDCIn(UDCWarn, v): return UDCClassWarn
	case UDCIn(UDCAllow, v): return UDCClassAllow
	default: return UDCClassUnknown
	}
}
