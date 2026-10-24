package main

// e69cyrillicextdcatalogguard.go —— 西里尔扩展 D 码位目录。
//
// 威胁模型：
//   扩展 D 西里尔字符含与拉丁近似的历史字形，常规字段无正当用途，
//   机器字段应拒绝。纯字符查表，不用正则。

const (
	E69T43ClassBlock   = "block"
	E69T43ClassWarn    = "warn"
	E69T43ClassAllow   = "allow"
	E69T43ClassUnknown = "unknown"
)

var E69T43Block = []string{
	"U+1E000",
	"U+1E001",
	"U+1E002",
	"U+1E003",
	"U+1E004",
	"U+1E005",
	"U+1E006",
	"U+1E007",
	"U+1E008",
	"U+1E009",
	"U+1E00A",
	"U+1E00B",
	"U+1E00C",
	"U+1E00D",
	"U+1E00E",
	"U+1E00F",
	"U+1E010",
	"U+1E011",
	"U+1E012",
	"U+1E013",
	"U+1E014",
	"U+1E015",
	"U+1E016",
	"U+1E017",
	"U+1E018",
	"U+1E019",
	"U+1E01A",
	"U+1E01B",
	"U+1E01C",
	"U+1E01D",
	"U+1E01E",
	"U+1E01F",
	"U+1E020",
	"U+1E021",
	"U+1E022",
	"U+1E023",
	"U+1E024",
	"U+1E025",
	"U+1E026",
	"U+1E027",
	"U+1E028",
	"U+1E029",
	"U+1E02A",
	"U+1E02B",
	"U+1E02C",
	"U+1E02D",
	"U+1E02E",
	"U+1E02F",
}

var E69T43Warn = []string{
}

var E69T43Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T43Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T43In(list []string, v string) bool {
	for _, x := range list { if E69T43Lower(x) == v { return true } }
	return false
}

// E69T43Classify 分类单个令牌。
func E69T43Classify(tok string) string {
	v := E69T43Lower(tok)
	switch {
	case E69T43In(E69T43Block, v): return E69T43ClassBlock
	case E69T43In(E69T43Warn, v): return E69T43ClassWarn
	case E69T43In(E69T43Allow, v): return E69T43ClassAllow
	default: return E69T43ClassUnknown
	}
}
