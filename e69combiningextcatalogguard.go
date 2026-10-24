package main

// e69combiningextcatalogguard.go —— 组合附加符扩展码位目录。
//
// 威胁模型：
//   扩展组合附加符叠加产生同形串，不同规范化形式可绕过匹配，
//   应 NFKC 归一化并剥离。纯字符查表，不用正则。

const (
	E69T37ClassBlock   = "block"
	E69T37ClassWarn    = "warn"
	E69T37ClassAllow   = "allow"
	E69T37ClassUnknown = "unknown"
)

var E69T37Block = []string{
}

var E69T37Warn = []string{
	"U+1AB0",
	"U+1AB1",
	"U+1AB2",
	"U+1AB3",
	"U+1AB4",
	"U+1AB5",
	"U+1AB6",
	"U+1AB7",
	"U+1AB8",
	"U+1AB9",
	"U+1ABA",
	"U+1ABB",
	"U+1ABC",
	"U+1ABD",
	"U+1ABE",
	"U+1ABF",
	"U+1AC0",
	"U+1AC1",
	"U+1AC2",
	"U+1AC3",
	"U+1AC4",
	"U+1AC5",
	"U+1AC6",
	"U+1AC7",
	"U+1AC8",
	"U+1AC9",
	"U+1ACA",
	"U+1ACB",
	"U+1ACC",
	"U+1ACD",
	"U+1ACE",
	"U+1ACF",
	"U+1AD0",
	"U+1AD1",
	"U+1AD2",
	"U+1AD3",
	"U+1AD4",
	"U+1AD5",
	"U+1AD6",
	"U+1AD7",
	"U+1AD8",
	"U+1AD9",
	"U+1ADA",
	"U+1ADB",
	"U+1ADC",
	"U+1ADD",
	"U+1ADE",
	"U+1ADF",
	"U+1AE0",
	"U+1AE1",
	"U+1AE2",
	"U+1AE3",
	"U+1AE4",
	"U+1AE5",
	"U+1AE6",
	"U+1AE7",
	"U+1AE8",
	"U+1AE9",
	"U+1AEA",
	"U+1AEB",
	"U+1AEC",
	"U+1AED",
	"U+1AEE",
	"U+1AEF",
	"U+1AF0",
	"U+1AF1",
	"U+1AF2",
	"U+1AF3",
	"U+1AF4",
	"U+1AF5",
	"U+1AF6",
	"U+1AF7",
	"U+1AF8",
	"U+1AF9",
	"U+1AFA",
	"U+1AFB",
	"U+1AFC",
	"U+1AFD",
	"U+1AFE",
	"U+1AFF",
}

var E69T37Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T37Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T37In(list []string, v string) bool {
	for _, x := range list { if E69T37Lower(x) == v { return true } }
	return false
}

// E69T37Classify 分类单个令牌。
func E69T37Classify(tok string) string {
	v := E69T37Lower(tok)
	switch {
	case E69T37In(E69T37Block, v): return E69T37ClassBlock
	case E69T37In(E69T37Warn, v): return E69T37ClassWarn
	case E69T37In(E69T37Allow, v): return E69T37ClassAllow
	default: return E69T37ClassUnknown
	}
}
