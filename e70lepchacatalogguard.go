package main

// e70lepchacatalogguard.go —— 雷布查文字码位目录。
//
// 威胁模型：
//   雷布查文在机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T32ClassBlock   = "block"
	E70T32ClassWarn    = "warn"
	E70T32ClassAllow   = "allow"
	E70T32ClassUnknown = "unknown"
)

var E70T32Block = []string{
	"U+1C00",
	"U+1C01",
	"U+1C02",
	"U+1C03",
	"U+1C04",
	"U+1C05",
	"U+1C06",
	"U+1C07",
	"U+1C08",
	"U+1C09",
	"U+1C0A",
	"U+1C0B",
	"U+1C0C",
	"U+1C0D",
	"U+1C0E",
	"U+1C0F",
	"U+1C10",
	"U+1C11",
	"U+1C12",
	"U+1C13",
	"U+1C14",
	"U+1C15",
	"U+1C16",
	"U+1C17",
	"U+1C18",
	"U+1C19",
	"U+1C1A",
	"U+1C1B",
	"U+1C1C",
	"U+1C1D",
	"U+1C1E",
	"U+1C1F",
	"U+1C20",
	"U+1C21",
	"U+1C22",
	"U+1C23",
	"U+1C24",
	"U+1C25",
	"U+1C26",
	"U+1C27",
	"U+1C28",
	"U+1C29",
	"U+1C2A",
	"U+1C2B",
	"U+1C2C",
	"U+1C2D",
	"U+1C2E",
	"U+1C2F",
	"U+1C30",
	"U+1C31",
	"U+1C32",
	"U+1C33",
	"U+1C34",
	"U+1C35",
	"U+1C36",
	"U+1C37",
	"U+1C38",
	"U+1C39",
	"U+1C3A",
	"U+1C3B",
	"U+1C3C",
	"U+1C3D",
	"U+1C3E",
	"U+1C3F",
	"U+1C40",
	"U+1C41",
	"U+1C42",
	"U+1C43",
	"U+1C44",
	"U+1C45",
	"U+1C46",
	"U+1C47",
	"U+1C48",
	"U+1C49",
	"U+1C4A",
	"U+1C4B",
	"U+1C4C",
	"U+1C4D",
	"U+1C4E",
	"U+1C4F",
}

var E70T32Warn = []string{
}

var E70T32Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T32Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T32In(list []string, v string) bool {
	for _, x := range list { if E70T32Lower(x) == v { return true } }
	return false
}

// E70T32Classify 分类单个令牌。
func E70T32Classify(tok string) string {
	v := E70T32Lower(tok)
	switch {
	case E70T32In(E70T32Block, v): return E70T32ClassBlock
	case E70T32In(E70T32Warn, v): return E70T32ClassWarn
	case E70T32In(E70T32Allow, v): return E70T32ClassAllow
	default: return E70T32ClassUnknown
	}
}
