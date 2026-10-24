package main

// e69generalpunctuationcatalogguard.go —— 通用标点符号码位目录。
//
// 威胁模型：
//   该块含零宽空格 U+200B、LRM/RLM、RLO U+202E 与双向隔离符 2066-2069，是隐藏字符与顺序欺骗核心区域，
//   应剥离零宽/双向控制后再判定。纯字符查表，不用正则。

const (
	E69T21ClassBlock   = "block"
	E69T21ClassWarn    = "warn"
	E69T21ClassAllow   = "allow"
	E69T21ClassUnknown = "unknown"
)

var E69T21Block = []string{
}

var E69T21Warn = []string{
	"U+2000",
	"U+2001",
	"U+2002",
	"U+2003",
	"U+2004",
	"U+2005",
	"U+2006",
	"U+2007",
	"U+2008",
	"U+2009",
	"U+200A",
	"U+200B",
	"U+200C",
	"U+200D",
	"U+200E",
	"U+200F",
	"U+2010",
	"U+2011",
	"U+2012",
	"U+2013",
	"U+2014",
	"U+2015",
	"U+2016",
	"U+2017",
	"U+2018",
	"U+2019",
	"U+201A",
	"U+201B",
	"U+201C",
	"U+201D",
	"U+201E",
	"U+201F",
	"U+2020",
	"U+2021",
	"U+2022",
	"U+2023",
	"U+2024",
	"U+2025",
	"U+2026",
	"U+2027",
	"U+2028",
	"U+2029",
	"U+202A",
	"U+202B",
	"U+202C",
	"U+202D",
	"U+202E",
	"U+202F",
	"U+2030",
	"U+2031",
	"U+2032",
	"U+2033",
	"U+2034",
	"U+2035",
	"U+2036",
	"U+2037",
	"U+2038",
	"U+2039",
	"U+203A",
	"U+203B",
	"U+203C",
	"U+203D",
	"U+203E",
	"U+203F",
	"U+2040",
	"U+2041",
	"U+2042",
	"U+2043",
	"U+2044",
	"U+2045",
	"U+2046",
	"U+2047",
	"U+2048",
	"U+2049",
	"U+204A",
	"U+204B",
	"U+204C",
	"U+204D",
	"U+204E",
	"U+204F",
	"U+2050",
	"U+2051",
	"U+2052",
	"U+2053",
	"U+2054",
	"U+2055",
	"U+2056",
	"U+2057",
	"U+2058",
	"U+2059",
	"U+205A",
	"U+205B",
	"U+205C",
	"U+205D",
	"U+205E",
	"U+205F",
	"U+2060",
	"U+2061",
	"U+2062",
	"U+2063",
	"U+2064",
	"U+2065",
	"U+2066",
	"U+2067",
	"U+2068",
	"U+2069",
	"U+206A",
	"U+206B",
	"U+206C",
	"U+206D",
	"U+206E",
	"U+206F",
}

var E69T21Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T21Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T21In(list []string, v string) bool {
	for _, x := range list { if E69T21Lower(x) == v { return true } }
	return false
}

// E69T21Classify 分类单个令牌。
func E69T21Classify(tok string) string {
	v := E69T21Lower(tok)
	switch {
	case E69T21In(E69T21Block, v): return E69T21ClassBlock
	case E69T21In(E69T21Warn, v): return E69T21ClassWarn
	case E69T21In(E69T21Allow, v): return E69T21ClassAllow
	default: return E69T21ClassUnknown
	}
}
