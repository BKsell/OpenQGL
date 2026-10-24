package main

// e69combininghalfmarkscatalogguard.go —— 组合半记号码位目录。
//
// 威胁模型：
//   组合半记号用于连字连接控制，常规字段无正当用途，可改变断字结果，
//   应拒绝。纯字符查表，不用正则。

const (
	E69T39ClassBlock   = "block"
	E69T39ClassWarn    = "warn"
	E69T39ClassAllow   = "allow"
	E69T39ClassUnknown = "unknown"
)

var E69T39Block = []string{
	"U+FE20",
	"U+FE21",
	"U+FE22",
	"U+FE23",
	"U+FE24",
	"U+FE25",
	"U+FE26",
	"U+FE27",
	"U+FE28",
	"U+FE29",
	"U+FE2A",
	"U+FE2B",
	"U+FE2C",
	"U+FE2D",
	"U+FE2E",
	"U+FE2F",
}

var E69T39Warn = []string{
}

var E69T39Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T39Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T39In(list []string, v string) bool {
	for _, x := range list { if E69T39Lower(x) == v { return true } }
	return false
}

// E69T39Classify 分类单个令牌。
func E69T39Classify(tok string) string {
	v := E69T39Lower(tok)
	switch {
	case E69T39In(E69T39Block, v): return E69T39ClassBlock
	case E69T39In(E69T39Warn, v): return E69T39ClassWarn
	case E69T39In(E69T39Allow, v): return E69T39ClassAllow
	default: return E69T39ClassUnknown
	}
}
