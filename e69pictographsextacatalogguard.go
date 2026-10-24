package main

// e69pictographsextacatalogguard.go —— 象形符号扩展 A 平面目录。
//
// 威胁模型：
//   扩展象形符号在机器字段无正当用途，旧系统可能无法渲染而隐藏内容，
//   结构化字段应拒绝。纯字符查表，不用正则。

const (
	E69U05ClassBlock   = "block"
	E69U05ClassWarn    = "warn"
	E69U05ClassAllow   = "allow"
	E69U05ClassUnknown = "unknown"
)

var E69U05Block = []string{
	"U+1FA70",
	"U+1FA71",
	"U+1FA72",
	"U+1FA73",
	"U+1FA74",
	"U+1FA75",
	"U+1FA76",
	"U+1FA77",
	"U+1FA78",
	"U+1FA79",
	"U+1FA7A",
	"U+1FA7B",
	"U+1FA7C",
	"U+1FA7D",
	"U+1FA7E",
	"U+1FA7F",
	"U+1FA80",
	"U+1FA81",
	"U+1FA82",
	"U+1FA83",
	"U+1FA84",
	"U+1FA85",
	"U+1FA86",
	"U+1FA87",
	"U+1FA88",
	"U+1FA89",
	"U+1FA8A",
	"U+1FA8B",
	"U+1FA8C",
	"U+1FA8D",
	"U+1FA8E",
	"U+1FA8F",
	"U+1FA90",
	"U+1FA91",
	"U+1FA92",
	"U+1FA93",
	"U+1FA94",
	"U+1FA95",
	"U+1FA96",
	"U+1FA97",
	"U+1FA98",
	"U+1FA99",
	"U+1FA9A",
	"U+1FA9B",
	"U+1FA9C",
	"U+1FA9D",
	"U+1FA9E",
	"U+1FA9F",
	"U+1FAA0",
	"U+1FAA1",
	"U+1FAA2",
	"U+1FAA3",
	"U+1FAA4",
	"U+1FAA5",
	"U+1FAA6",
	"U+1FAA7",
	"U+1FAA8",
	"U+1FAA9",
	"U+1FAAA",
	"U+1FAAB",
	"U+1FAAC",
	"U+1FAAD",
	"U+1FAAE",
	"U+1FAAF",
	"U+1FAB0",
	"U+1FAB1",
	"U+1FAB2",
	"U+1FAB3",
	"U+1FAB4",
	"U+1FAB5",
	"U+1FAB6",
	"U+1FAB7",
	"U+1FAB8",
	"U+1FAB9",
	"U+1FABA",
	"U+1FABB",
	"U+1FABC",
	"U+1FABD",
	"U+1FABE",
	"U+1FABF",
	"U+1FAC0",
	"U+1FAC1",
	"U+1FAC2",
	"U+1FAC3",
	"U+1FAC4",
	"U+1FAC5",
	"U+1FAC6",
	"U+1FAC7",
	"U+1FAC8",
	"U+1FAC9",
	"U+1FACA",
	"U+1FACB",
	"U+1FACC",
	"U+1FACD",
	"U+1FACE",
	"U+1FACF",
	"U+1FAD0",
	"U+1FAD1",
	"U+1FAD2",
	"U+1FAD3",
	"U+1FAD4",
	"U+1FAD5",
	"U+1FAD6",
	"U+1FAD7",
	"U+1FAD8",
	"U+1FAD9",
	"U+1FADA",
	"U+1FADB",
	"U+1FADC",
	"U+1FADD",
	"U+1FADE",
	"U+1FADF",
	"U+1FAE0",
	"U+1FAE1",
	"U+1FAE2",
	"U+1FAE3",
	"U+1FAE4",
	"U+1FAE5",
	"U+1FAE6",
	"U+1FAE7",
	"U+1FAE8",
	"U+1FAE9",
	"U+1FAEA",
	"U+1FAEB",
	"U+1FAEC",
	"U+1FAED",
	"U+1FAEE",
	"U+1FAEF",
	"U+1FAF0",
	"U+1FAF1",
	"U+1FAF2",
	"U+1FAF3",
	"U+1FAF4",
	"U+1FAF5",
	"U+1FAF6",
	"U+1FAF7",
	"U+1FAF8",
	"U+1FAF9",
	"U+1FAFA",
	"U+1FAFB",
	"U+1FAFC",
	"U+1FAFD",
	"U+1FAFE",
	"U+1FAFF",
}

var E69U05Warn = []string{
}

var E69U05Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69U05Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69U05In(list []string, v string) bool {
	for _, x := range list { if E69U05Lower(x) == v { return true } }
	return false
}

// E69U05Classify 分类单个令牌。
func E69U05Classify(tok string) string {
	v := E69U05Lower(tok)
	switch {
	case E69U05In(E69U05Block, v): return E69U05ClassBlock
	case E69U05In(E69U05Warn, v): return E69U05ClassWarn
	case E69U05In(E69U05Allow, v): return E69U05ClassAllow
	default: return E69U05ClassUnknown
	}
}
