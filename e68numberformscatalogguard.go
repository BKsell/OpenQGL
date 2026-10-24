package main

// e68numberformscatalogguard.go —— 数字形式码位目录。
//
// 威胁模型：
//   分数/罗马数字形式与 ASCII 数字视觉等价，数值解析前需规范化，
//   应 NFKC 归一化。纯字符查表，不用正则。

const (
	E68R25ClassBlock   = "block"
	E68R25ClassWarn    = "warn"
	E68R25ClassAllow   = "allow"
	E68R25ClassUnknown = "unknown"
)

var E68R25Block = []string{
}

var E68R25Warn = []string{
	"U+2150",
	"U+2151",
	"U+2152",
	"U+2153",
	"U+2154",
	"U+2155",
	"U+2156",
	"U+2157",
	"U+2158",
	"U+2159",
	"U+215A",
	"U+215B",
	"U+215C",
	"U+215D",
	"U+215E",
	"U+215F",
	"U+2160",
	"U+2161",
	"U+2162",
	"U+2163",
	"U+2164",
	"U+2165",
	"U+2166",
	"U+2167",
	"U+2168",
	"U+2169",
	"U+216A",
	"U+216B",
	"U+216C",
	"U+216D",
	"U+216E",
	"U+216F",
	"U+2170",
	"U+2171",
	"U+2172",
	"U+2173",
	"U+2174",
	"U+2175",
	"U+2176",
	"U+2177",
	"U+2178",
	"U+2179",
	"U+217A",
	"U+217B",
	"U+217C",
	"U+217D",
	"U+217E",
	"U+217F",
	"U+2180",
	"U+2181",
	"U+2182",
	"U+2183",
	"U+2184",
	"U+2185",
	"U+2186",
	"U+2187",
	"U+2188",
	"U+2189",
	"U+218A",
	"U+218B",
	"U+218C",
	"U+218D",
	"U+218E",
	"U+218F",
}

var E68R25Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R25Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R25In(list []string, v string) bool {
	for _, x := range list { if E68R25Lower(x) == v { return true } }
	return false
}

// E68R25Classify 分类单个令牌。
func E68R25Classify(tok string) string {
	v := E68R25Lower(tok)
	switch {
	case E68R25In(E68R25Block, v): return E68R25ClassBlock
	case E68R25In(E68R25Warn, v): return E68R25ClassWarn
	case E68R25In(E68R25Allow, v): return E68R25ClassAllow
	default: return E68R25ClassUnknown
	}
}
