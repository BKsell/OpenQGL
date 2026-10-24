package main

// e68letterlikecatalogguard.go —— 字母式符号码位目录。
//
// 威胁模型：
//   U+212A 开尔文 K、U+212B 埃等与拉丁字母同形，是经典同形攻击字符，
//   应 NFKC 归一化后判定。纯字符查表，不用正则。

const (
	E68R24ClassBlock   = "block"
	E68R24ClassWarn    = "warn"
	E68R24ClassAllow   = "allow"
	E68R24ClassUnknown = "unknown"
)

var E68R24Block = []string{
}

var E68R24Warn = []string{
	"U+2100",
	"U+2101",
	"U+2102",
	"U+2103",
	"U+2104",
	"U+2105",
	"U+2106",
	"U+2107",
	"U+2108",
	"U+2109",
	"U+210A",
	"U+210B",
	"U+210C",
	"U+210D",
	"U+210E",
	"U+210F",
	"U+2110",
	"U+2111",
	"U+2112",
	"U+2113",
	"U+2114",
	"U+2115",
	"U+2116",
	"U+2117",
	"U+2118",
	"U+2119",
	"U+211A",
	"U+211B",
	"U+211C",
	"U+211D",
	"U+211E",
	"U+211F",
	"U+2120",
	"U+2121",
	"U+2122",
	"U+2123",
	"U+2124",
	"U+2125",
	"U+2126",
	"U+2127",
	"U+2128",
	"U+2129",
	"U+212A",
	"U+212B",
	"U+212C",
	"U+212D",
	"U+212E",
	"U+212F",
	"U+2130",
	"U+2131",
	"U+2132",
	"U+2133",
	"U+2134",
	"U+2135",
	"U+2136",
	"U+2137",
	"U+2138",
	"U+2139",
	"U+213A",
	"U+213B",
	"U+213C",
	"U+213D",
	"U+213E",
	"U+213F",
	"U+2140",
	"U+2141",
	"U+2142",
	"U+2143",
	"U+2144",
	"U+2145",
	"U+2146",
	"U+2147",
	"U+2148",
	"U+2149",
	"U+214A",
	"U+214B",
	"U+214C",
	"U+214D",
	"U+214E",
	"U+214F",
}

var E68R24Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R24Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R24In(list []string, v string) bool {
	for _, x := range list { if E68R24Lower(x) == v { return true } }
	return false
}

// E68R24Classify 分类单个令牌。
func E68R24Classify(tok string) string {
	v := E68R24Lower(tok)
	switch {
	case E68R24In(E68R24Block, v): return E68R24ClassBlock
	case E68R24In(E68R24Warn, v): return E68R24ClassWarn
	case E68R24In(E68R24Allow, v): return E68R24ClassAllow
	default: return E68R24ClassUnknown
	}
}
