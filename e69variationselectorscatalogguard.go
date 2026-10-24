package main

// e69variationselectorscatalogguard.go —— 变体选择符码位目录。
//
// 威胁模型：
//   VS1-VS16 本身不可见却改变前一字符的字形选择，可让同一码点序列渲染成不同符号，
//   机器字段应拒绝。纯字符查表，不用正则。

const (
	E69T40ClassBlock   = "block"
	E69T40ClassWarn    = "warn"
	E69T40ClassAllow   = "allow"
	E69T40ClassUnknown = "unknown"
)

var E69T40Block = []string{
	"U+FE00",
	"U+FE01",
	"U+FE02",
	"U+FE03",
	"U+FE04",
	"U+FE05",
	"U+FE06",
	"U+FE07",
	"U+FE08",
	"U+FE09",
	"U+FE0A",
	"U+FE0B",
	"U+FE0C",
	"U+FE0D",
	"U+FE0E",
	"U+FE0F",
}

var E69T40Warn = []string{
}

var E69T40Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T40Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T40In(list []string, v string) bool {
	for _, x := range list { if E69T40Lower(x) == v { return true } }
	return false
}

// E69T40Classify 分类单个令牌。
func E69T40Classify(tok string) string {
	v := E69T40Lower(tok)
	switch {
	case E69T40In(E69T40Block, v): return E69T40ClassBlock
	case E69T40In(E69T40Warn, v): return E69T40ClassWarn
	case E69T40In(E69T40Allow, v): return E69T40ClassAllow
	default: return E69T40ClassUnknown
	}
}
