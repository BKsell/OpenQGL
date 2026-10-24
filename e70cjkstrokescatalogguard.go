package main

// e70cjkstrokescatalogguard.go —— CJK 笔画码位目录。
//
// 威胁模型：
//   CJK 笔画字符在机器字段无正当用途，与部件形似可混淆匹配，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T56ClassBlock   = "block"
	E70T56ClassWarn    = "warn"
	E70T56ClassAllow   = "allow"
	E70T56ClassUnknown = "unknown"
)

var E70T56Block = []string{
	"U+31A0",
	"U+31A1",
	"U+31A2",
	"U+31A3",
	"U+31A4",
	"U+31A5",
	"U+31A6",
	"U+31A7",
	"U+31A8",
	"U+31A9",
	"U+31AA",
	"U+31AB",
	"U+31AC",
	"U+31AD",
	"U+31AE",
	"U+31AF",
	"U+31B0",
	"U+31B1",
	"U+31B2",
	"U+31B3",
	"U+31B4",
	"U+31B5",
	"U+31B6",
	"U+31B7",
	"U+31B8",
	"U+31B9",
	"U+31BA",
	"U+31BB",
	"U+31BC",
	"U+31BD",
	"U+31BE",
	"U+31BF",
}

var E70T56Warn = []string{
}

var E70T56Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T56Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T56In(list []string, v string) bool {
	for _, x := range list { if E70T56Lower(x) == v { return true } }
	return false
}

// E70T56Classify 分类单个令牌。
func E70T56Classify(tok string) string {
	v := E70T56Lower(tok)
	switch {
	case E70T56In(E70T56Block, v): return E70T56ClassBlock
	case E70T56In(E70T56Warn, v): return E70T56ClassWarn
	case E70T56In(E70T56Allow, v): return E70T56ClassAllow
	default: return E70T56ClassUnknown
	}
}
