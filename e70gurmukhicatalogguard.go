package main

// e70gurmukhicatalogguard.go —— 古木基文字码位目录。
//
// 威胁模型：
//   古木基文在常规机器字段无正当用途，缺字体时不可见，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T11ClassBlock   = "block"
	E70T11ClassWarn    = "warn"
	E70T11ClassAllow   = "allow"
	E70T11ClassUnknown = "unknown"
)

var E70T11Block = []string{
	"U+0A00",
	"U+0A01",
	"U+0A02",
	"U+0A03",
	"U+0A04",
	"U+0A05",
	"U+0A06",
	"U+0A07",
	"U+0A08",
	"U+0A09",
	"U+0A0A",
	"U+0A0B",
	"U+0A0C",
	"U+0A0D",
	"U+0A0E",
	"U+0A0F",
	"U+0A10",
	"U+0A11",
	"U+0A12",
	"U+0A13",
	"U+0A14",
	"U+0A15",
	"U+0A16",
	"U+0A17",
	"U+0A18",
	"U+0A19",
	"U+0A1A",
	"U+0A1B",
	"U+0A1C",
	"U+0A1D",
	"U+0A1E",
	"U+0A1F",
	"U+0A20",
	"U+0A21",
	"U+0A22",
	"U+0A23",
	"U+0A24",
	"U+0A25",
	"U+0A26",
	"U+0A27",
	"U+0A28",
	"U+0A29",
	"U+0A2A",
	"U+0A2B",
	"U+0A2C",
	"U+0A2D",
	"U+0A2E",
	"U+0A2F",
	"U+0A30",
	"U+0A31",
	"U+0A32",
	"U+0A33",
	"U+0A34",
	"U+0A35",
	"U+0A36",
	"U+0A37",
	"U+0A38",
	"U+0A39",
	"U+0A3A",
	"U+0A3B",
	"U+0A3C",
	"U+0A3D",
	"U+0A3E",
	"U+0A3F",
	"U+0A40",
	"U+0A41",
	"U+0A42",
	"U+0A43",
	"U+0A44",
	"U+0A45",
	"U+0A46",
	"U+0A47",
	"U+0A48",
	"U+0A49",
	"U+0A4A",
	"U+0A4B",
	"U+0A4C",
	"U+0A4D",
	"U+0A4E",
	"U+0A4F",
	"U+0A50",
	"U+0A51",
	"U+0A52",
	"U+0A53",
	"U+0A54",
	"U+0A55",
	"U+0A56",
	"U+0A57",
	"U+0A58",
	"U+0A59",
	"U+0A5A",
	"U+0A5B",
	"U+0A5C",
	"U+0A5D",
	"U+0A5E",
	"U+0A5F",
	"U+0A60",
	"U+0A61",
	"U+0A62",
	"U+0A63",
	"U+0A64",
	"U+0A65",
	"U+0A66",
	"U+0A67",
	"U+0A68",
	"U+0A69",
	"U+0A6A",
	"U+0A6B",
	"U+0A6C",
	"U+0A6D",
	"U+0A6E",
	"U+0A6F",
	"U+0A70",
	"U+0A71",
	"U+0A72",
	"U+0A73",
	"U+0A74",
	"U+0A75",
	"U+0A76",
	"U+0A77",
	"U+0A78",
	"U+0A79",
	"U+0A7A",
	"U+0A7B",
	"U+0A7C",
	"U+0A7D",
	"U+0A7E",
	"U+0A7F",
}

var E70T11Warn = []string{
}

var E70T11Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T11Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T11In(list []string, v string) bool {
	for _, x := range list { if E70T11Lower(x) == v { return true } }
	return false
}

// E70T11Classify 分类单个令牌。
func E70T11Classify(tok string) string {
	v := E70T11Lower(tok)
	switch {
	case E70T11In(E70T11Block, v): return E70T11ClassBlock
	case E70T11In(E70T11Warn, v): return E70T11ClassWarn
	case E70T11In(E70T11Allow, v): return E70T11ClassAllow
	default: return E70T11ClassUnknown
	}
}
