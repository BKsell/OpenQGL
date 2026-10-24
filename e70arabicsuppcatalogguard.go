package main

// e70arabicsuppcatalogguard.go —— 阿拉伯文补充码位目录。
//
// 威胁模型：
//   阿拉伯文补充字符同样参与连写与双向排版，机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T04ClassBlock   = "block"
	E70T04ClassWarn    = "warn"
	E70T04ClassAllow   = "allow"
	E70T04ClassUnknown = "unknown"
)

var E70T04Block = []string{
	"U+0750",
	"U+0751",
	"U+0752",
	"U+0753",
	"U+0754",
	"U+0755",
	"U+0756",
	"U+0757",
	"U+0758",
	"U+0759",
	"U+075A",
	"U+075B",
	"U+075C",
	"U+075D",
	"U+075E",
	"U+075F",
	"U+0760",
	"U+0761",
	"U+0762",
	"U+0763",
	"U+0764",
	"U+0765",
	"U+0766",
	"U+0767",
	"U+0768",
	"U+0769",
	"U+076A",
	"U+076B",
	"U+076C",
	"U+076D",
	"U+076E",
	"U+076F",
	"U+0770",
	"U+0771",
	"U+0772",
	"U+0773",
	"U+0774",
	"U+0775",
	"U+0776",
	"U+0777",
	"U+0778",
	"U+0779",
	"U+077A",
	"U+077B",
	"U+077C",
	"U+077D",
	"U+077E",
	"U+077F",
}

var E70T04Warn = []string{
}

var E70T04Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T04Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T04In(list []string, v string) bool {
	for _, x := range list { if E70T04Lower(x) == v { return true } }
	return false
}

// E70T04Classify 分类单个令牌。
func E70T04Classify(tok string) string {
	v := E70T04Lower(tok)
	switch {
	case E70T04In(E70T04Block, v): return E70T04ClassBlock
	case E70T04In(E70T04Warn, v): return E70T04ClassWarn
	case E70T04In(E70T04Allow, v): return E70T04ClassAllow
	default: return E70T04ClassUnknown
	}
}
