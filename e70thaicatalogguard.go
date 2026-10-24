package main

// e70thaicatalogguard.go —— 泰文字码位目录。
//
// 威胁模型：
//   泰文不带空格分词且含组合记号，混排可改变断字与显示宽度，
//   结构化字段应拒绝。纯字符查表，不用正则。

const (
	E70T19ClassBlock   = "block"
	E70T19ClassWarn    = "warn"
	E70T19ClassAllow   = "allow"
	E70T19ClassUnknown = "unknown"
)

var E70T19Block = []string{
	"U+0E00",
	"U+0E01",
	"U+0E02",
	"U+0E03",
	"U+0E04",
	"U+0E05",
	"U+0E06",
	"U+0E07",
	"U+0E08",
	"U+0E09",
	"U+0E0A",
	"U+0E0B",
	"U+0E0C",
	"U+0E0D",
	"U+0E0E",
	"U+0E0F",
	"U+0E10",
	"U+0E11",
	"U+0E12",
	"U+0E13",
	"U+0E14",
	"U+0E15",
	"U+0E16",
	"U+0E17",
	"U+0E18",
	"U+0E19",
	"U+0E1A",
	"U+0E1B",
	"U+0E1C",
	"U+0E1D",
	"U+0E1E",
	"U+0E1F",
	"U+0E20",
	"U+0E21",
	"U+0E22",
	"U+0E23",
	"U+0E24",
	"U+0E25",
	"U+0E26",
	"U+0E27",
	"U+0E28",
	"U+0E29",
	"U+0E2A",
	"U+0E2B",
	"U+0E2C",
	"U+0E2D",
	"U+0E2E",
	"U+0E2F",
	"U+0E30",
	"U+0E31",
	"U+0E32",
	"U+0E33",
	"U+0E34",
	"U+0E35",
	"U+0E36",
	"U+0E37",
	"U+0E38",
	"U+0E39",
	"U+0E3A",
	"U+0E3B",
	"U+0E3C",
	"U+0E3D",
	"U+0E3E",
	"U+0E3F",
	"U+0E40",
	"U+0E41",
	"U+0E42",
	"U+0E43",
	"U+0E44",
	"U+0E45",
	"U+0E46",
	"U+0E47",
	"U+0E48",
	"U+0E49",
	"U+0E4A",
	"U+0E4B",
	"U+0E4C",
	"U+0E4D",
	"U+0E4E",
	"U+0E4F",
	"U+0E50",
	"U+0E51",
	"U+0E52",
	"U+0E53",
	"U+0E54",
	"U+0E55",
	"U+0E56",
	"U+0E57",
	"U+0E58",
	"U+0E59",
	"U+0E5A",
	"U+0E5B",
	"U+0E5C",
	"U+0E5D",
	"U+0E5E",
	"U+0E5F",
	"U+0E60",
	"U+0E61",
	"U+0E62",
	"U+0E63",
	"U+0E64",
	"U+0E65",
	"U+0E66",
	"U+0E67",
	"U+0E68",
	"U+0E69",
	"U+0E6A",
	"U+0E6B",
	"U+0E6C",
	"U+0E6D",
	"U+0E6E",
	"U+0E6F",
	"U+0E70",
	"U+0E71",
	"U+0E72",
	"U+0E73",
	"U+0E74",
	"U+0E75",
	"U+0E76",
	"U+0E77",
	"U+0E78",
	"U+0E79",
	"U+0E7A",
	"U+0E7B",
	"U+0E7C",
	"U+0E7D",
	"U+0E7E",
	"U+0E7F",
}

var E70T19Warn = []string{
}

var E70T19Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T19Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T19In(list []string, v string) bool {
	for _, x := range list { if E70T19Lower(x) == v { return true } }
	return false
}

// E70T19Classify 分类单个令牌。
func E70T19Classify(tok string) string {
	v := E70T19Lower(tok)
	switch {
	case E70T19In(E70T19Block, v): return E70T19ClassBlock
	case E70T19In(E70T19Warn, v): return E70T19ClassWarn
	case E70T19In(E70T19Allow, v): return E70T19ClassAllow
	default: return E70T19ClassUnknown
	}
}
