package main

// e70mandaiccatalogguard.go —— 曼达文字码位目录。
//
// 威胁模型：
//   曼达文字罕用且从右向左，可用于在字段中隐藏非预期内容，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T08ClassBlock   = "block"
	E70T08ClassWarn    = "warn"
	E70T08ClassAllow   = "allow"
	E70T08ClassUnknown = "unknown"
)

var E70T08Block = []string{
	"U+0840",
	"U+0841",
	"U+0842",
	"U+0843",
	"U+0844",
	"U+0845",
	"U+0846",
	"U+0847",
	"U+0848",
	"U+0849",
	"U+084A",
	"U+084B",
	"U+084C",
	"U+084D",
	"U+084E",
	"U+084F",
	"U+0850",
	"U+0851",
	"U+0852",
	"U+0853",
	"U+0854",
	"U+0855",
	"U+0856",
	"U+0857",
	"U+0858",
	"U+0859",
	"U+085A",
	"U+085B",
	"U+085C",
	"U+085D",
	"U+085E",
	"U+085F",
}

var E70T08Warn = []string{
}

var E70T08Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T08Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T08In(list []string, v string) bool {
	for _, x := range list { if E70T08Lower(x) == v { return true } }
	return false
}

// E70T08Classify 分类单个令牌。
func E70T08Classify(tok string) string {
	v := E70T08Lower(tok)
	switch {
	case E70T08In(E70T08Block, v): return E70T08ClassBlock
	case E70T08In(E70T08Warn, v): return E70T08ClassWarn
	case E70T08In(E70T08Allow, v): return E70T08ClassAllow
	default: return E70T08ClassUnknown
	}
}
