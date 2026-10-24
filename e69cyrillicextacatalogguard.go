package main

// e69cyrillicextacatalogguard.go —— 西里尔扩展 A 码位目录。
//
// 威胁模型：
//   扩展西里尔组合/修饰字符在常规字段无正当用途，可用于序列混淆，
//   应拒绝。纯字符查表，不用正则。

const (
	E69T18ClassBlock   = "block"
	E69T18ClassWarn    = "warn"
	E69T18ClassAllow   = "allow"
	E69T18ClassUnknown = "unknown"
)

var E69T18Block = []string{
	"U+2DE0",
	"U+2DE1",
	"U+2DE2",
	"U+2DE3",
	"U+2DE4",
	"U+2DE5",
	"U+2DE6",
	"U+2DE7",
	"U+2DE8",
	"U+2DE9",
	"U+2DEA",
	"U+2DEB",
	"U+2DEC",
	"U+2DED",
	"U+2DEE",
	"U+2DEF",
	"U+2DF0",
	"U+2DF1",
	"U+2DF2",
	"U+2DF3",
	"U+2DF4",
	"U+2DF5",
	"U+2DF6",
	"U+2DF7",
	"U+2DF8",
	"U+2DF9",
	"U+2DFA",
	"U+2DFB",
	"U+2DFC",
	"U+2DFD",
	"U+2DFE",
	"U+2DFF",
}

var E69T18Warn = []string{
}

var E69T18Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T18Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T18In(list []string, v string) bool {
	for _, x := range list { if E69T18Lower(x) == v { return true } }
	return false
}

// E69T18Classify 分类单个令牌。
func E69T18Classify(tok string) string {
	v := E69T18Lower(tok)
	switch {
	case E69T18In(E69T18Block, v): return E69T18ClassBlock
	case E69T18In(E69T18Warn, v): return E69T18ClassWarn
	case E69T18In(E69T18Allow, v): return E69T18ClassAllow
	default: return E69T18ClassUnknown
	}
}
