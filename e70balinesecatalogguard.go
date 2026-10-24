package main

// e70balinesecatalogguard.go —— 巴厘文字码位目录。
//
// 威胁模型：
//   巴厘文组合记号复杂，可在视觉位堆叠码点，
//   结构化字段应拒绝。纯字符查表，不用正则。

const (
	E70T29ClassBlock   = "block"
	E70T29ClassWarn    = "warn"
	E70T29ClassAllow   = "allow"
	E70T29ClassUnknown = "unknown"
)

var E70T29Block = []string{
	"U+1B00",
	"U+1B01",
	"U+1B02",
	"U+1B03",
	"U+1B04",
	"U+1B05",
	"U+1B06",
	"U+1B07",
	"U+1B08",
	"U+1B09",
	"U+1B0A",
	"U+1B0B",
	"U+1B0C",
	"U+1B0D",
	"U+1B0E",
	"U+1B0F",
	"U+1B10",
	"U+1B11",
	"U+1B12",
	"U+1B13",
	"U+1B14",
	"U+1B15",
	"U+1B16",
	"U+1B17",
	"U+1B18",
	"U+1B19",
	"U+1B1A",
	"U+1B1B",
	"U+1B1C",
	"U+1B1D",
	"U+1B1E",
	"U+1B1F",
	"U+1B20",
	"U+1B21",
	"U+1B22",
	"U+1B23",
	"U+1B24",
	"U+1B25",
	"U+1B26",
	"U+1B27",
	"U+1B28",
	"U+1B29",
	"U+1B2A",
	"U+1B2B",
	"U+1B2C",
	"U+1B2D",
	"U+1B2E",
	"U+1B2F",
	"U+1B30",
	"U+1B31",
	"U+1B32",
	"U+1B33",
	"U+1B34",
	"U+1B35",
	"U+1B36",
	"U+1B37",
	"U+1B38",
	"U+1B39",
	"U+1B3A",
	"U+1B3B",
	"U+1B3C",
	"U+1B3D",
	"U+1B3E",
	"U+1B3F",
	"U+1B40",
	"U+1B41",
	"U+1B42",
	"U+1B43",
	"U+1B44",
	"U+1B45",
	"U+1B46",
	"U+1B47",
	"U+1B48",
	"U+1B49",
	"U+1B4A",
	"U+1B4B",
	"U+1B4C",
	"U+1B4D",
	"U+1B4E",
	"U+1B4F",
	"U+1B50",
	"U+1B51",
	"U+1B52",
	"U+1B53",
	"U+1B54",
	"U+1B55",
	"U+1B56",
	"U+1B57",
	"U+1B58",
	"U+1B59",
	"U+1B5A",
	"U+1B5B",
	"U+1B5C",
	"U+1B5D",
	"U+1B5E",
	"U+1B5F",
	"U+1B60",
	"U+1B61",
	"U+1B62",
	"U+1B63",
	"U+1B64",
	"U+1B65",
	"U+1B66",
	"U+1B67",
	"U+1B68",
	"U+1B69",
	"U+1B6A",
	"U+1B6B",
	"U+1B6C",
	"U+1B6D",
	"U+1B6E",
	"U+1B6F",
	"U+1B70",
	"U+1B71",
	"U+1B72",
	"U+1B73",
	"U+1B74",
	"U+1B75",
	"U+1B76",
	"U+1B77",
	"U+1B78",
	"U+1B79",
	"U+1B7A",
	"U+1B7B",
	"U+1B7C",
	"U+1B7D",
	"U+1B7E",
	"U+1B7F",
}

var E70T29Warn = []string{
}

var E70T29Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T29Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T29In(list []string, v string) bool {
	for _, x := range list { if E70T29Lower(x) == v { return true } }
	return false
}

// E70T29Classify 分类单个令牌。
func E70T29Classify(tok string) string {
	v := E70T29Lower(tok)
	switch {
	case E70T29In(E70T29Block, v): return E70T29ClassBlock
	case E70T29In(E70T29Warn, v): return E70T29ClassWarn
	case E70T29In(E70T29Allow, v): return E70T29ClassAllow
	default: return E70T29ClassUnknown
	}
}
