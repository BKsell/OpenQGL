package main

// e70supplementalpunctcatalogguard.go —— 补充标点码位目录。
//
// 威胁模型：
//   补充标点含历史标点与特殊分隔符，可替换 ASCII 标点绕过匹配，
//   机器字段应拒绝。纯字符查表，不用正则。

const (
	E70T55ClassBlock   = "block"
	E70T55ClassWarn    = "warn"
	E70T55ClassAllow   = "allow"
	E70T55ClassUnknown = "unknown"
)

var E70T55Block = []string{
	"U+2E00",
	"U+2E01",
	"U+2E02",
	"U+2E03",
	"U+2E04",
	"U+2E05",
	"U+2E06",
	"U+2E07",
	"U+2E08",
	"U+2E09",
	"U+2E0A",
	"U+2E0B",
	"U+2E0C",
	"U+2E0D",
	"U+2E0E",
	"U+2E0F",
	"U+2E10",
	"U+2E11",
	"U+2E12",
	"U+2E13",
	"U+2E14",
	"U+2E15",
	"U+2E16",
	"U+2E17",
	"U+2E18",
	"U+2E19",
	"U+2E1A",
	"U+2E1B",
	"U+2E1C",
	"U+2E1D",
	"U+2E1E",
	"U+2E1F",
	"U+2E20",
	"U+2E21",
	"U+2E22",
	"U+2E23",
	"U+2E24",
	"U+2E25",
	"U+2E26",
	"U+2E27",
	"U+2E28",
	"U+2E29",
	"U+2E2A",
	"U+2E2B",
	"U+2E2C",
	"U+2E2D",
	"U+2E2E",
	"U+2E2F",
	"U+2E30",
	"U+2E31",
	"U+2E32",
	"U+2E33",
	"U+2E34",
	"U+2E35",
	"U+2E36",
	"U+2E37",
	"U+2E38",
	"U+2E39",
	"U+2E3A",
	"U+2E3B",
	"U+2E3C",
	"U+2E3D",
	"U+2E3E",
	"U+2E3F",
	"U+2E40",
	"U+2E41",
	"U+2E42",
	"U+2E43",
	"U+2E44",
	"U+2E45",
	"U+2E46",
	"U+2E47",
	"U+2E48",
	"U+2E49",
	"U+2E4A",
	"U+2E4B",
	"U+2E4C",
	"U+2E4D",
	"U+2E4E",
	"U+2E4F",
	"U+2E50",
	"U+2E51",
	"U+2E52",
	"U+2E53",
	"U+2E54",
	"U+2E55",
	"U+2E56",
	"U+2E57",
	"U+2E58",
	"U+2E59",
	"U+2E5A",
	"U+2E5B",
	"U+2E5C",
	"U+2E5D",
	"U+2E5E",
	"U+2E5F",
	"U+2E60",
	"U+2E61",
	"U+2E62",
	"U+2E63",
	"U+2E64",
	"U+2E65",
	"U+2E66",
	"U+2E67",
	"U+2E68",
	"U+2E69",
	"U+2E6A",
	"U+2E6B",
	"U+2E6C",
	"U+2E6D",
	"U+2E6E",
	"U+2E6F",
	"U+2E70",
	"U+2E71",
	"U+2E72",
	"U+2E73",
	"U+2E74",
	"U+2E75",
	"U+2E76",
	"U+2E77",
	"U+2E78",
	"U+2E79",
	"U+2E7A",
	"U+2E7B",
	"U+2E7C",
	"U+2E7D",
	"U+2E7E",
	"U+2E7F",
}

var E70T55Warn = []string{
}

var E70T55Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T55Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T55In(list []string, v string) bool {
	for _, x := range list { if E70T55Lower(x) == v { return true } }
	return false
}

// E70T55Classify 分类单个令牌。
func E70T55Classify(tok string) string {
	v := E70T55Lower(tok)
	switch {
	case E70T55In(E70T55Block, v): return E70T55ClassBlock
	case E70T55In(E70T55Warn, v): return E70T55ClassWarn
	case E70T55In(E70T55Allow, v): return E70T55ClassAllow
	default: return E70T55ClassUnknown
	}
}
