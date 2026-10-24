package main

// e70numberformscatalogguard.go —— 数字形式码位目录。
//
// 威胁模型：
//   ½ ⅓ Ⅷ 等数字形式与普通数字串长度/形态不同，规范化后变化，可绕过数值匹配，
//   应 NFKC 归一化。纯字符查表，不用正则。

const (
	E70T39ClassBlock   = "block"
	E70T39ClassWarn    = "warn"
	E70T39ClassAllow   = "allow"
	E70T39ClassUnknown = "unknown"
)

var E70T39Block = []string{
}

var E70T39Warn = []string{
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

var E70T39Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T39Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T39In(list []string, v string) bool {
	for _, x := range list { if E70T39Lower(x) == v { return true } }
	return false
}

// E70T39Classify 分类单个令牌。
func E70T39Classify(tok string) string {
	v := E70T39Lower(tok)
	switch {
	case E70T39In(E70T39Block, v): return E70T39ClassBlock
	case E70T39In(E70T39Warn, v): return E70T39ClassWarn
	case E70T39In(E70T39Allow, v): return E70T39ClassAllow
	default: return E70T39ClassUnknown
	}
}
