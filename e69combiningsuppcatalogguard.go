package main

// e69combiningsuppcatalogguard.go —— 组合附加符补充码位目录。
//
// 威胁模型：
//   补充组合记号覆盖上标/附加显示，视觉与码位序列不一致，
//   应 NFKC 归一化并剥离。纯字符查表，不用正则。

const (
	E69T38ClassBlock   = "block"
	E69T38ClassWarn    = "warn"
	E69T38ClassAllow   = "allow"
	E69T38ClassUnknown = "unknown"
)

var E69T38Block = []string{
}

var E69T38Warn = []string{
	"U+1DC0",
	"U+1DC1",
	"U+1DC2",
	"U+1DC3",
	"U+1DC4",
	"U+1DC5",
	"U+1DC6",
	"U+1DC7",
	"U+1DC8",
	"U+1DC9",
	"U+1DCA",
	"U+1DCB",
	"U+1DCC",
	"U+1DCD",
	"U+1DCE",
	"U+1DCF",
	"U+1DD0",
	"U+1DD1",
	"U+1DD2",
	"U+1DD3",
	"U+1DD4",
	"U+1DD5",
	"U+1DD6",
	"U+1DD7",
	"U+1DD8",
	"U+1DD9",
	"U+1DDA",
	"U+1DDB",
	"U+1DDC",
	"U+1DDD",
	"U+1DDE",
	"U+1DDF",
	"U+1DE0",
	"U+1DE1",
	"U+1DE2",
	"U+1DE3",
	"U+1DE4",
	"U+1DE5",
	"U+1DE6",
	"U+1DE7",
	"U+1DE8",
	"U+1DE9",
	"U+1DEA",
	"U+1DEB",
	"U+1DEC",
	"U+1DED",
	"U+1DEE",
	"U+1DEF",
	"U+1DF0",
	"U+1DF1",
	"U+1DF2",
	"U+1DF3",
	"U+1DF4",
	"U+1DF5",
	"U+1DF6",
	"U+1DF7",
	"U+1DF8",
	"U+1DF9",
	"U+1DFA",
	"U+1DFB",
	"U+1DFC",
	"U+1DFD",
	"U+1DFE",
	"U+1DFF",
}

var E69T38Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T38Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T38In(list []string, v string) bool {
	for _, x := range list { if E69T38Lower(x) == v { return true } }
	return false
}

// E69T38Classify 分类单个令牌。
func E69T38Classify(tok string) string {
	v := E69T38Lower(tok)
	switch {
	case E69T38In(E69T38Block, v): return E69T38ClassBlock
	case E69T38In(E69T38Warn, v): return E69T38ClassWarn
	case E69T38In(E69T38Allow, v): return E69T38ClassAllow
	default: return E69T38ClassUnknown
	}
}
