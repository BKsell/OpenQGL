package main

// e69cyrillicsuppcatalogguard.go —— 西里尔文字补充码位目录。
//
// 威胁模型：
//   补充西里尔字母同样存在与拉丁混排的同形风险，
//   应规范化后比较。纯字符查表，不用正则。

const (
	E69T08ClassBlock   = "block"
	E69T08ClassWarn    = "warn"
	E69T08ClassAllow   = "allow"
	E69T08ClassUnknown = "unknown"
)

var E69T08Block = []string{
}

var E69T08Warn = []string{
	"U+0500",
	"U+0501",
	"U+0502",
	"U+0503",
	"U+0504",
	"U+0505",
	"U+0506",
	"U+0507",
	"U+0508",
	"U+0509",
	"U+050A",
	"U+050B",
	"U+050C",
	"U+050D",
	"U+050E",
	"U+050F",
	"U+0510",
	"U+0511",
	"U+0512",
	"U+0513",
	"U+0514",
	"U+0515",
	"U+0516",
	"U+0517",
	"U+0518",
	"U+0519",
	"U+051A",
	"U+051B",
	"U+051C",
	"U+051D",
	"U+051E",
	"U+051F",
	"U+0520",
	"U+0521",
	"U+0522",
	"U+0523",
	"U+0524",
	"U+0525",
	"U+0526",
	"U+0527",
	"U+0528",
	"U+0529",
	"U+052A",
	"U+052B",
	"U+052C",
	"U+052D",
	"U+052E",
	"U+052F",
}

var E69T08Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T08Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T08In(list []string, v string) bool {
	for _, x := range list { if E69T08Lower(x) == v { return true } }
	return false
}

// E69T08Classify 分类单个令牌。
func E69T08Classify(tok string) string {
	v := E69T08Lower(tok)
	switch {
	case E69T08In(E69T08Block, v): return E69T08ClassBlock
	case E69T08In(E69T08Warn, v): return E69T08ClassWarn
	case E69T08In(E69T08Allow, v): return E69T08ClassAllow
	default: return E69T08ClassUnknown
	}
}
