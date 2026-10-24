package main

// e68sinhalacatalogguard.go —— 僧伽罗文字码位目录。
//
// 威胁模型：
//   僧伽罗文组合符可构成同形字符串，
//   标识符使用需复核。纯字符查表，不用正则。

const (
	E68R14ClassBlock   = "block"
	E68R14ClassWarn    = "warn"
	E68R14ClassAllow   = "allow"
	E68R14ClassUnknown = "unknown"
)

var E68R14Block = []string{
}

var E68R14Warn = []string{
	"U+0D80",
	"U+0D81",
	"U+0D82",
	"U+0D83",
	"U+0D84",
	"U+0D85",
	"U+0D86",
	"U+0D87",
	"U+0D88",
	"U+0D89",
	"U+0D8A",
	"U+0D8B",
	"U+0D8C",
	"U+0D8D",
	"U+0D8E",
	"U+0D8F",
	"U+0D90",
	"U+0D91",
	"U+0D92",
	"U+0D93",
	"U+0D94",
	"U+0D95",
	"U+0D96",
	"U+0D97",
	"U+0D98",
	"U+0D99",
	"U+0D9A",
	"U+0D9B",
	"U+0D9C",
	"U+0D9D",
	"U+0D9E",
	"U+0D9F",
	"U+0DA0",
	"U+0DA1",
	"U+0DA2",
	"U+0DA3",
	"U+0DA4",
	"U+0DA5",
	"U+0DA6",
	"U+0DA7",
	"U+0DA8",
	"U+0DA9",
	"U+0DAA",
	"U+0DAB",
	"U+0DAC",
	"U+0DAD",
	"U+0DAE",
	"U+0DAF",
	"U+0DB0",
	"U+0DB1",
	"U+0DB2",
	"U+0DB3",
	"U+0DB4",
	"U+0DB5",
	"U+0DB6",
	"U+0DB7",
	"U+0DB8",
	"U+0DB9",
	"U+0DBA",
	"U+0DBB",
	"U+0DBC",
	"U+0DBD",
	"U+0DBE",
	"U+0DBF",
	"U+0DC0",
	"U+0DC1",
	"U+0DC2",
	"U+0DC3",
	"U+0DC4",
	"U+0DC5",
	"U+0DC6",
	"U+0DC7",
	"U+0DC8",
	"U+0DC9",
	"U+0DCA",
	"U+0DCB",
	"U+0DCC",
	"U+0DCD",
	"U+0DCE",
	"U+0DCF",
	"U+0DD0",
	"U+0DD1",
	"U+0DD2",
	"U+0DD3",
	"U+0DD4",
	"U+0DD5",
	"U+0DD6",
	"U+0DD7",
	"U+0DD8",
	"U+0DD9",
	"U+0DDA",
	"U+0DDB",
	"U+0DDC",
	"U+0DDD",
	"U+0DDE",
	"U+0DDF",
	"U+0DE0",
	"U+0DE1",
	"U+0DE2",
	"U+0DE3",
	"U+0DE4",
	"U+0DE5",
	"U+0DE6",
	"U+0DE7",
	"U+0DE8",
	"U+0DE9",
	"U+0DEA",
	"U+0DEB",
	"U+0DEC",
	"U+0DED",
	"U+0DEE",
	"U+0DEF",
	"U+0DF0",
	"U+0DF1",
	"U+0DF2",
	"U+0DF3",
	"U+0DF4",
	"U+0DF5",
	"U+0DF6",
	"U+0DF7",
	"U+0DF8",
	"U+0DF9",
	"U+0DFA",
	"U+0DFB",
	"U+0DFC",
	"U+0DFD",
	"U+0DFE",
	"U+0DFF",
}

var E68R14Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R14Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R14In(list []string, v string) bool {
	for _, x := range list { if E68R14Lower(x) == v { return true } }
	return false
}

// E68R14Classify 分类单个令牌。
func E68R14Classify(tok string) string {
	v := E68R14Lower(tok)
	switch {
	case E68R14In(E68R14Block, v): return E68R14ClassBlock
	case E68R14In(E68R14Warn, v): return E68R14ClassWarn
	case E68R14In(E68R14Allow, v): return E68R14ClassAllow
	default: return E68R14ClassUnknown
	}
}
