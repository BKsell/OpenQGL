package main

// e69mahjongdominocatalogguard.go —— 麻将与多米诺骨牌目录。
//
// 威胁模型：
//   麻将/多米诺符号在机器字段无正当用途，可用于界面符号仿冒，
//   结构化字段应拒绝。纯字符查表，不用正则。

const (
	E69U11ClassBlock   = "block"
	E69U11ClassWarn    = "warn"
	E69U11ClassAllow   = "allow"
	E69U11ClassUnknown = "unknown"
)

var E69U11Block = []string{
	"U+1F000",
	"U+1F001",
	"U+1F002",
	"U+1F003",
	"U+1F004",
	"U+1F005",
	"U+1F006",
	"U+1F007",
	"U+1F008",
	"U+1F009",
	"U+1F00A",
	"U+1F00B",
	"U+1F00C",
	"U+1F00D",
	"U+1F00E",
	"U+1F00F",
	"U+1F010",
	"U+1F011",
	"U+1F012",
	"U+1F013",
	"U+1F014",
	"U+1F015",
	"U+1F016",
	"U+1F017",
	"U+1F018",
	"U+1F019",
	"U+1F01A",
	"U+1F01B",
	"U+1F01C",
	"U+1F01D",
	"U+1F01E",
	"U+1F01F",
	"U+1F020",
	"U+1F021",
	"U+1F022",
	"U+1F023",
	"U+1F024",
	"U+1F025",
	"U+1F026",
	"U+1F027",
	"U+1F028",
	"U+1F029",
	"U+1F02A",
	"U+1F02B",
	"U+1F02C",
	"U+1F02D",
	"U+1F02E",
	"U+1F02F",
}

var E69U11Warn = []string{
}

var E69U11Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69U11Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69U11In(list []string, v string) bool {
	for _, x := range list { if E69U11Lower(x) == v { return true } }
	return false
}

// E69U11Classify 分类单个令牌。
func E69U11Classify(tok string) string {
	v := E69U11Lower(tok)
	switch {
	case E69U11In(E69U11Block, v): return E69U11ClassBlock
	case E69U11In(E69U11Warn, v): return E69U11ClassWarn
	case E69U11In(E69U11Allow, v): return E69U11ClassAllow
	default: return E69U11ClassUnknown
	}
}
