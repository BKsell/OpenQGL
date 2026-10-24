package main

// e70georgiansuppcatalogguard.go —— 格鲁吉亚补充码位目录。
//
// 威胁模型：
//   格鲁吉亚补充字符在机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T53ClassBlock   = "block"
	E70T53ClassWarn    = "warn"
	E70T53ClassAllow   = "allow"
	E70T53ClassUnknown = "unknown"
)

var E70T53Block = []string{
	"U+2D00",
	"U+2D01",
	"U+2D02",
	"U+2D03",
	"U+2D04",
	"U+2D05",
	"U+2D06",
	"U+2D07",
	"U+2D08",
	"U+2D09",
	"U+2D0A",
	"U+2D0B",
	"U+2D0C",
	"U+2D0D",
	"U+2D0E",
	"U+2D0F",
	"U+2D10",
	"U+2D11",
	"U+2D12",
	"U+2D13",
	"U+2D14",
	"U+2D15",
	"U+2D16",
	"U+2D17",
	"U+2D18",
	"U+2D19",
	"U+2D1A",
	"U+2D1B",
	"U+2D1C",
	"U+2D1D",
	"U+2D1E",
	"U+2D1F",
	"U+2D20",
	"U+2D21",
	"U+2D22",
	"U+2D23",
	"U+2D24",
	"U+2D25",
	"U+2D26",
	"U+2D27",
	"U+2D28",
	"U+2D29",
	"U+2D2A",
	"U+2D2B",
	"U+2D2C",
	"U+2D2D",
	"U+2D2E",
	"U+2D2F",
}

var E70T53Warn = []string{
}

var E70T53Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T53Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T53In(list []string, v string) bool {
	for _, x := range list { if E70T53Lower(x) == v { return true } }
	return false
}

// E70T53Classify 分类单个令牌。
func E70T53Classify(tok string) string {
	v := E70T53Lower(tok)
	switch {
	case E70T53In(E70T53Block, v): return E70T53ClassBlock
	case E70T53In(E70T53Warn, v): return E70T53ClassWarn
	case E70T53In(E70T53Allow, v): return E70T53ClassAllow
	default: return E70T53ClassUnknown
	}
}
