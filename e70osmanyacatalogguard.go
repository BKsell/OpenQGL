package main

// e70osmanyacatalogguard.go —— 奥斯曼亚字母平面目录。
//
// 威胁模型：
//   奥斯曼亚字母罕用、渲染依赖字体，可隐藏载荷，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70U07ClassBlock   = "block"
	E70U07ClassWarn    = "warn"
	E70U07ClassAllow   = "allow"
	E70U07ClassUnknown = "unknown"
)

var E70U07Block = []string{
	"U+10480",
	"U+10481",
	"U+10482",
	"U+10483",
	"U+10484",
	"U+10485",
	"U+10486",
	"U+10487",
	"U+10488",
	"U+10489",
	"U+1048A",
	"U+1048B",
	"U+1048C",
	"U+1048D",
	"U+1048E",
	"U+1048F",
	"U+10490",
	"U+10491",
	"U+10492",
	"U+10493",
	"U+10494",
	"U+10495",
	"U+10496",
	"U+10497",
	"U+10498",
	"U+10499",
	"U+1049A",
	"U+1049B",
	"U+1049C",
	"U+1049D",
	"U+1049E",
	"U+1049F",
	"U+104A0",
	"U+104A1",
	"U+104A2",
	"U+104A3",
	"U+104A4",
	"U+104A5",
	"U+104A6",
	"U+104A7",
	"U+104A8",
	"U+104A9",
	"U+104AA",
	"U+104AB",
	"U+104AC",
	"U+104AD",
	"U+104AE",
	"U+104AF",
}

var E70U07Warn = []string{
}

var E70U07Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70U07Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70U07In(list []string, v string) bool {
	for _, x := range list { if E70U07Lower(x) == v { return true } }
	return false
}

// E70U07Classify 分类单个令牌。
func E70U07Classify(tok string) string {
	v := E70U07Lower(tok)
	switch {
	case E70U07In(E70U07Block, v): return E70U07ClassBlock
	case E70U07In(E70U07Warn, v): return E70U07ClassWarn
	case E70U07In(E70U07Allow, v): return E70U07ClassAllow
	default: return E70U07ClassUnknown
	}
}
