package main

// e70samaritancatalogguard.go —— 撒玛利亚文字码位目录。
//
// 威胁模型：
//   撒玛利亚文字罕用、渲染依赖专用字体，机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T07ClassBlock   = "block"
	E70T07ClassWarn    = "warn"
	E70T07ClassAllow   = "allow"
	E70T07ClassUnknown = "unknown"
)

var E70T07Block = []string{
	"U+0800",
	"U+0801",
	"U+0802",
	"U+0803",
	"U+0804",
	"U+0805",
	"U+0806",
	"U+0807",
	"U+0808",
	"U+0809",
	"U+080A",
	"U+080B",
	"U+080C",
	"U+080D",
	"U+080E",
	"U+080F",
	"U+0810",
	"U+0811",
	"U+0812",
	"U+0813",
	"U+0814",
	"U+0815",
	"U+0816",
	"U+0817",
	"U+0818",
	"U+0819",
	"U+081A",
	"U+081B",
	"U+081C",
	"U+081D",
	"U+081E",
	"U+081F",
	"U+0820",
	"U+0821",
	"U+0822",
	"U+0823",
	"U+0824",
	"U+0825",
	"U+0826",
	"U+0827",
	"U+0828",
	"U+0829",
	"U+082A",
	"U+082B",
	"U+082C",
	"U+082D",
	"U+082E",
	"U+082F",
	"U+0830",
	"U+0831",
	"U+0832",
	"U+0833",
	"U+0834",
	"U+0835",
	"U+0836",
	"U+0837",
	"U+0838",
	"U+0839",
	"U+083A",
	"U+083B",
	"U+083C",
	"U+083D",
	"U+083E",
	"U+083F",
}

var E70T07Warn = []string{
}

var E70T07Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T07Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T07In(list []string, v string) bool {
	for _, x := range list { if E70T07Lower(x) == v { return true } }
	return false
}

// E70T07Classify 分类单个令牌。
func E70T07Classify(tok string) string {
	v := E70T07Lower(tok)
	switch {
	case E70T07In(E70T07Block, v): return E70T07ClassBlock
	case E70T07In(E70T07Warn, v): return E70T07ClassWarn
	case E70T07In(E70T07Allow, v): return E70T07ClassAllow
	default: return E70T07ClassUnknown
	}
}
