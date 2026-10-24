package main

// e69smallformvariantscatalogguard.go —— 小型形式变体标点码位目录。
//
// 威胁模型：
//   ﹨ ﹤ ﹥ 等小型标点与 ASCII 反斜杠/尖括号视觉近似，是路径与标签混淆来源，
//   应 NFKC 归一化。纯字符查表，不用正则。

const (
	E69T34ClassBlock   = "block"
	E69T34ClassWarn    = "warn"
	E69T34ClassAllow   = "allow"
	E69T34ClassUnknown = "unknown"
)

var E69T34Block = []string{
}

var E69T34Warn = []string{
	"U+FE50",
	"U+FE51",
	"U+FE52",
	"U+FE53",
	"U+FE54",
	"U+FE55",
	"U+FE56",
	"U+FE57",
	"U+FE58",
	"U+FE59",
	"U+FE5A",
	"U+FE5B",
	"U+FE5C",
	"U+FE5D",
	"U+FE5E",
	"U+FE5F",
	"U+FE60",
	"U+FE61",
	"U+FE62",
	"U+FE63",
	"U+FE64",
	"U+FE65",
	"U+FE66",
	"U+FE67",
	"U+FE68",
	"U+FE69",
	"U+FE6A",
	"U+FE6B",
	"U+FE6C",
	"U+FE6D",
	"U+FE6E",
	"U+FE6F",
}

var E69T34Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T34Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T34In(list []string, v string) bool {
	for _, x := range list { if E69T34Lower(x) == v { return true } }
	return false
}

// E69T34Classify 分类单个令牌。
func E69T34Classify(tok string) string {
	v := E69T34Lower(tok)
	switch {
	case E69T34In(E69T34Block, v): return E69T34ClassBlock
	case E69T34In(E69T34Warn, v): return E69T34ClassWarn
	case E69T34In(E69T34Allow, v): return E69T34ClassAllow
	default: return E69T34ClassUnknown
	}
}
