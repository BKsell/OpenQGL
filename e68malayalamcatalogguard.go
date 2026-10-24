package main

// e68malayalamcatalogguard.go —— 马拉雅拉姆文字码位目录。
//
// 威胁模型：
//   马拉雅拉姆文含复杂连写，视觉与码位序列差异大，
//   应 NFKC 归一化。纯字符查表，不用正则。

const (
	E68R13ClassBlock   = "block"
	E68R13ClassWarn    = "warn"
	E68R13ClassAllow   = "allow"
	E68R13ClassUnknown = "unknown"
)

var E68R13Block = []string{
}

var E68R13Warn = []string{
	"U+0D00",
	"U+0D01",
	"U+0D02",
	"U+0D03",
	"U+0D04",
	"U+0D05",
	"U+0D06",
	"U+0D07",
	"U+0D08",
	"U+0D09",
	"U+0D0A",
	"U+0D0B",
	"U+0D0C",
	"U+0D0D",
	"U+0D0E",
	"U+0D0F",
	"U+0D10",
	"U+0D11",
	"U+0D12",
	"U+0D13",
	"U+0D14",
	"U+0D15",
	"U+0D16",
	"U+0D17",
	"U+0D18",
	"U+0D19",
	"U+0D1A",
	"U+0D1B",
	"U+0D1C",
	"U+0D1D",
	"U+0D1E",
	"U+0D1F",
	"U+0D20",
	"U+0D21",
	"U+0D22",
	"U+0D23",
	"U+0D24",
	"U+0D25",
	"U+0D26",
	"U+0D27",
	"U+0D28",
	"U+0D29",
	"U+0D2A",
	"U+0D2B",
	"U+0D2C",
	"U+0D2D",
	"U+0D2E",
	"U+0D2F",
	"U+0D30",
	"U+0D31",
	"U+0D32",
	"U+0D33",
	"U+0D34",
	"U+0D35",
	"U+0D36",
	"U+0D37",
	"U+0D38",
	"U+0D39",
	"U+0D3A",
	"U+0D3B",
	"U+0D3C",
	"U+0D3D",
	"U+0D3E",
	"U+0D3F",
	"U+0D40",
	"U+0D41",
	"U+0D42",
	"U+0D43",
	"U+0D44",
	"U+0D45",
	"U+0D46",
	"U+0D47",
	"U+0D48",
	"U+0D49",
	"U+0D4A",
	"U+0D4B",
	"U+0D4C",
	"U+0D4D",
	"U+0D4E",
	"U+0D4F",
	"U+0D50",
	"U+0D51",
	"U+0D52",
	"U+0D53",
	"U+0D54",
	"U+0D55",
	"U+0D56",
	"U+0D57",
	"U+0D58",
	"U+0D59",
	"U+0D5A",
	"U+0D5B",
	"U+0D5C",
	"U+0D5D",
	"U+0D5E",
	"U+0D5F",
	"U+0D60",
	"U+0D61",
	"U+0D62",
	"U+0D63",
	"U+0D64",
	"U+0D65",
	"U+0D66",
	"U+0D67",
	"U+0D68",
	"U+0D69",
	"U+0D6A",
	"U+0D6B",
	"U+0D6C",
	"U+0D6D",
	"U+0D6E",
	"U+0D6F",
	"U+0D70",
	"U+0D71",
	"U+0D72",
	"U+0D73",
	"U+0D74",
	"U+0D75",
	"U+0D76",
	"U+0D77",
	"U+0D78",
	"U+0D79",
	"U+0D7A",
	"U+0D7B",
	"U+0D7C",
	"U+0D7D",
	"U+0D7E",
	"U+0D7F",
}

var E68R13Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R13Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R13In(list []string, v string) bool {
	for _, x := range list { if E68R13Lower(x) == v { return true } }
	return false
}

// E68R13Classify 分类单个令牌。
func E68R13Classify(tok string) string {
	v := E68R13Lower(tok)
	switch {
	case E68R13In(E68R13Block, v): return E68R13ClassBlock
	case E68R13In(E68R13Warn, v): return E68R13ClassWarn
	case E68R13In(E68R13Allow, v): return E68R13ClassAllow
	default: return E68R13ClassUnknown
	}
}
