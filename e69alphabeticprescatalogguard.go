package main

// e69alphabeticprescatalogguard.go —— 字母表示形式码位目录。
//
// 威胁模型：
//   ﬁ ﬂ 等连字在 NFKC 后展开为多字符 ASCII，规范化前后长度变化可绕过匹配，
//   应 NFKC 归一化。纯字符查表，不用正则。

const (
	E69T33ClassBlock   = "block"
	E69T33ClassWarn    = "warn"
	E69T33ClassAllow   = "allow"
	E69T33ClassUnknown = "unknown"
)

var E69T33Block = []string{
}

var E69T33Warn = []string{
	"U+FB00",
	"U+FB01",
	"U+FB02",
	"U+FB03",
	"U+FB04",
	"U+FB05",
	"U+FB06",
	"U+FB07",
	"U+FB08",
	"U+FB09",
	"U+FB0A",
	"U+FB0B",
	"U+FB0C",
	"U+FB0D",
	"U+FB0E",
	"U+FB0F",
	"U+FB10",
	"U+FB11",
	"U+FB12",
	"U+FB13",
	"U+FB14",
	"U+FB15",
	"U+FB16",
	"U+FB17",
	"U+FB18",
	"U+FB19",
	"U+FB1A",
	"U+FB1B",
	"U+FB1C",
	"U+FB1D",
	"U+FB1E",
	"U+FB1F",
	"U+FB20",
	"U+FB21",
	"U+FB22",
	"U+FB23",
	"U+FB24",
	"U+FB25",
	"U+FB26",
	"U+FB27",
	"U+FB28",
	"U+FB29",
	"U+FB2A",
	"U+FB2B",
	"U+FB2C",
	"U+FB2D",
	"U+FB2E",
	"U+FB2F",
	"U+FB30",
	"U+FB31",
	"U+FB32",
	"U+FB33",
	"U+FB34",
	"U+FB35",
	"U+FB36",
	"U+FB37",
	"U+FB38",
	"U+FB39",
	"U+FB3A",
	"U+FB3B",
	"U+FB3C",
	"U+FB3D",
	"U+FB3E",
	"U+FB3F",
	"U+FB40",
	"U+FB41",
	"U+FB42",
	"U+FB43",
	"U+FB44",
	"U+FB45",
	"U+FB46",
	"U+FB47",
	"U+FB48",
	"U+FB49",
	"U+FB4A",
	"U+FB4B",
	"U+FB4C",
	"U+FB4D",
	"U+FB4E",
	"U+FB4F",
}

var E69T33Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T33Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T33In(list []string, v string) bool {
	for _, x := range list { if E69T33Lower(x) == v { return true } }
	return false
}

// E69T33Classify 分类单个令牌。
func E69T33Classify(tok string) string {
	v := E69T33Lower(tok)
	switch {
	case E69T33In(E69T33Block, v): return E69T33ClassBlock
	case E69T33In(E69T33Warn, v): return E69T33ClassWarn
	case E69T33In(E69T33Allow, v): return E69T33ClassAllow
	default: return E69T33ClassUnknown
	}
}
