package main

// e70modifiertonecatalogguard.go —— 修饰声调字母码位目录。
//
// 威胁模型：
//   声调修饰字母与普通字母视觉近似且不占组合位，可绕过字形检查，
//   应规范化后比较。纯字符查表，不用正则。

const (
	E70T59ClassBlock   = "block"
	E70T59ClassWarn    = "warn"
	E70T59ClassAllow   = "allow"
	E70T59ClassUnknown = "unknown"
)

var E70T59Block = []string{
}

var E70T59Warn = []string{
	"U+A700",
	"U+A701",
	"U+A702",
	"U+A703",
	"U+A704",
	"U+A705",
	"U+A706",
	"U+A707",
	"U+A708",
	"U+A709",
	"U+A70A",
	"U+A70B",
	"U+A70C",
	"U+A70D",
	"U+A70E",
	"U+A70F",
	"U+A710",
	"U+A711",
	"U+A712",
	"U+A713",
	"U+A714",
	"U+A715",
	"U+A716",
	"U+A717",
	"U+A718",
	"U+A719",
	"U+A71A",
	"U+A71B",
	"U+A71C",
	"U+A71D",
	"U+A71E",
	"U+A71F",
}

var E70T59Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T59Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T59In(list []string, v string) bool {
	for _, x := range list { if E70T59Lower(x) == v { return true } }
	return false
}

// E70T59Classify 分类单个令牌。
func E70T59Classify(tok string) string {
	v := E70T59Lower(tok)
	switch {
	case E70T59In(E70T59Block, v): return E70T59ClassBlock
	case E70T59In(E70T59Warn, v): return E70T59ClassWarn
	case E70T59In(E70T59Allow, v): return E70T59ClassAllow
	default: return E70T59ClassUnknown
	}
}
