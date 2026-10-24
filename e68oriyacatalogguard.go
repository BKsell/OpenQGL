package main

// e68oriyacatalogguard.go —— 奥里亚文字码位目录。
//
// 威胁模型：
//   奥里亚文连写组合可绕过基于码点的关键字过滤，
//   应 NFKC 归一化。纯字符查表，不用正则。

const (
	E68R09ClassBlock   = "block"
	E68R09ClassWarn    = "warn"
	E68R09ClassAllow   = "allow"
	E68R09ClassUnknown = "unknown"
)

var E68R09Block = []string{
}

var E68R09Warn = []string{
	"U+0B00",
	"U+0B01",
	"U+0B02",
	"U+0B03",
	"U+0B04",
	"U+0B05",
	"U+0B06",
	"U+0B07",
	"U+0B08",
	"U+0B09",
	"U+0B0A",
	"U+0B0B",
	"U+0B0C",
	"U+0B0D",
	"U+0B0E",
	"U+0B0F",
	"U+0B10",
	"U+0B11",
	"U+0B12",
	"U+0B13",
	"U+0B14",
	"U+0B15",
	"U+0B16",
	"U+0B17",
	"U+0B18",
	"U+0B19",
	"U+0B1A",
	"U+0B1B",
	"U+0B1C",
	"U+0B1D",
	"U+0B1E",
	"U+0B1F",
	"U+0B20",
	"U+0B21",
	"U+0B22",
	"U+0B23",
	"U+0B24",
	"U+0B25",
	"U+0B26",
	"U+0B27",
	"U+0B28",
	"U+0B29",
	"U+0B2A",
	"U+0B2B",
	"U+0B2C",
	"U+0B2D",
	"U+0B2E",
	"U+0B2F",
	"U+0B30",
	"U+0B31",
	"U+0B32",
	"U+0B33",
	"U+0B34",
	"U+0B35",
	"U+0B36",
	"U+0B37",
	"U+0B38",
	"U+0B39",
	"U+0B3A",
	"U+0B3B",
	"U+0B3C",
	"U+0B3D",
	"U+0B3E",
	"U+0B3F",
	"U+0B40",
	"U+0B41",
	"U+0B42",
	"U+0B43",
	"U+0B44",
	"U+0B45",
	"U+0B46",
	"U+0B47",
	"U+0B48",
	"U+0B49",
	"U+0B4A",
	"U+0B4B",
	"U+0B4C",
	"U+0B4D",
	"U+0B4E",
	"U+0B4F",
	"U+0B50",
	"U+0B51",
	"U+0B52",
	"U+0B53",
	"U+0B54",
	"U+0B55",
	"U+0B56",
	"U+0B57",
	"U+0B58",
	"U+0B59",
	"U+0B5A",
	"U+0B5B",
	"U+0B5C",
	"U+0B5D",
	"U+0B5E",
	"U+0B5F",
	"U+0B60",
	"U+0B61",
	"U+0B62",
	"U+0B63",
	"U+0B64",
	"U+0B65",
	"U+0B66",
	"U+0B67",
	"U+0B68",
	"U+0B69",
	"U+0B6A",
	"U+0B6B",
	"U+0B6C",
	"U+0B6D",
	"U+0B6E",
	"U+0B6F",
	"U+0B70",
	"U+0B71",
	"U+0B72",
	"U+0B73",
	"U+0B74",
	"U+0B75",
	"U+0B76",
	"U+0B77",
	"U+0B78",
	"U+0B79",
	"U+0B7A",
	"U+0B7B",
	"U+0B7C",
	"U+0B7D",
	"U+0B7E",
	"U+0B7F",
}

var E68R09Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R09Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R09In(list []string, v string) bool {
	for _, x := range list { if E68R09Lower(x) == v { return true } }
	return false
}

// E68R09Classify 分类单个令牌。
func E68R09Classify(tok string) string {
	v := E68R09Lower(tok)
	switch {
	case E68R09In(E68R09Block, v): return E68R09ClassBlock
	case E68R09In(E68R09Warn, v): return E68R09ClassWarn
	case E68R09In(E68R09Allow, v): return E68R09ClassAllow
	default: return E68R09ClassUnknown
	}
}
