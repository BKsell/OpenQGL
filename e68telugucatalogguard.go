package main

// e68telugucatalogguard.go —— 泰卢固文字码位目录。
//
// 威胁模型：
//   泰卢固文附加符叠加构造同形，
//   标识符使用需复核。纯字符查表，不用正则。

const (
	E68R11ClassBlock   = "block"
	E68R11ClassWarn    = "warn"
	E68R11ClassAllow   = "allow"
	E68R11ClassUnknown = "unknown"
)

var E68R11Block = []string{
}

var E68R11Warn = []string{
	"U+0C00",
	"U+0C01",
	"U+0C02",
	"U+0C03",
	"U+0C04",
	"U+0C05",
	"U+0C06",
	"U+0C07",
	"U+0C08",
	"U+0C09",
	"U+0C0A",
	"U+0C0B",
	"U+0C0C",
	"U+0C0D",
	"U+0C0E",
	"U+0C0F",
	"U+0C10",
	"U+0C11",
	"U+0C12",
	"U+0C13",
	"U+0C14",
	"U+0C15",
	"U+0C16",
	"U+0C17",
	"U+0C18",
	"U+0C19",
	"U+0C1A",
	"U+0C1B",
	"U+0C1C",
	"U+0C1D",
	"U+0C1E",
	"U+0C1F",
	"U+0C20",
	"U+0C21",
	"U+0C22",
	"U+0C23",
	"U+0C24",
	"U+0C25",
	"U+0C26",
	"U+0C27",
	"U+0C28",
	"U+0C29",
	"U+0C2A",
	"U+0C2B",
	"U+0C2C",
	"U+0C2D",
	"U+0C2E",
	"U+0C2F",
	"U+0C30",
	"U+0C31",
	"U+0C32",
	"U+0C33",
	"U+0C34",
	"U+0C35",
	"U+0C36",
	"U+0C37",
	"U+0C38",
	"U+0C39",
	"U+0C3A",
	"U+0C3B",
	"U+0C3C",
	"U+0C3D",
	"U+0C3E",
	"U+0C3F",
	"U+0C40",
	"U+0C41",
	"U+0C42",
	"U+0C43",
	"U+0C44",
	"U+0C45",
	"U+0C46",
	"U+0C47",
	"U+0C48",
	"U+0C49",
	"U+0C4A",
	"U+0C4B",
	"U+0C4C",
	"U+0C4D",
	"U+0C4E",
	"U+0C4F",
	"U+0C50",
	"U+0C51",
	"U+0C52",
	"U+0C53",
	"U+0C54",
	"U+0C55",
	"U+0C56",
	"U+0C57",
	"U+0C58",
	"U+0C59",
	"U+0C5A",
	"U+0C5B",
	"U+0C5C",
	"U+0C5D",
	"U+0C5E",
	"U+0C5F",
	"U+0C60",
	"U+0C61",
	"U+0C62",
	"U+0C63",
	"U+0C64",
	"U+0C65",
	"U+0C66",
	"U+0C67",
	"U+0C68",
	"U+0C69",
	"U+0C6A",
	"U+0C6B",
	"U+0C6C",
	"U+0C6D",
	"U+0C6E",
	"U+0C6F",
	"U+0C70",
	"U+0C71",
	"U+0C72",
	"U+0C73",
	"U+0C74",
	"U+0C75",
	"U+0C76",
	"U+0C77",
	"U+0C78",
	"U+0C79",
	"U+0C7A",
	"U+0C7B",
	"U+0C7C",
	"U+0C7D",
	"U+0C7E",
	"U+0C7F",
}

var E68R11Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R11Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R11In(list []string, v string) bool {
	for _, x := range list { if E68R11Lower(x) == v { return true } }
	return false
}

// E68R11Classify 分类单个令牌。
func E68R11Classify(tok string) string {
	v := E68R11Lower(tok)
	switch {
	case E68R11In(E68R11Block, v): return E68R11ClassBlock
	case E68R11In(E68R11Warn, v): return E68R11ClassWarn
	case E68R11In(E68R11Allow, v): return E68R11ClassAllow
	default: return E68R11ClassUnknown
	}
}
