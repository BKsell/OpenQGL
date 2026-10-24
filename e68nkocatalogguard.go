package main

// e68nkocatalogguard.go —— NKo 文字码位目录。
//
// 威胁模型：
//   NKo 等罕用文字块在多数环境缺字体而无法稳定渲染，可承载不可见载荷，
//   标识符/路径中应直接拒绝。纯字符查表，不用正则。

const (
	E68R04ClassBlock   = "block"
	E68R04ClassWarn    = "warn"
	E68R04ClassAllow   = "allow"
	E68R04ClassUnknown = "unknown"
)

var E68R04Block = []string{
	"U+07C0",
	"U+07C1",
	"U+07C2",
	"U+07C3",
	"U+07C4",
	"U+07C5",
	"U+07C6",
	"U+07C7",
	"U+07C8",
	"U+07C9",
	"U+07CA",
	"U+07CB",
	"U+07CC",
	"U+07CD",
	"U+07CE",
	"U+07CF",
	"U+07D0",
	"U+07D1",
	"U+07D2",
	"U+07D3",
	"U+07D4",
	"U+07D5",
	"U+07D6",
	"U+07D7",
	"U+07D8",
	"U+07D9",
	"U+07DA",
	"U+07DB",
	"U+07DC",
	"U+07DD",
	"U+07DE",
	"U+07DF",
	"U+07E0",
	"U+07E1",
	"U+07E2",
	"U+07E3",
	"U+07E4",
	"U+07E5",
	"U+07E6",
	"U+07E7",
	"U+07E8",
	"U+07E9",
	"U+07EA",
	"U+07EB",
	"U+07EC",
	"U+07ED",
	"U+07EE",
	"U+07EF",
	"U+07F0",
	"U+07F1",
	"U+07F2",
	"U+07F3",
	"U+07F4",
	"U+07F5",
	"U+07F6",
	"U+07F7",
	"U+07F8",
	"U+07F9",
	"U+07FA",
	"U+07FB",
	"U+07FC",
	"U+07FD",
	"U+07FE",
	"U+07FF",
}

var E68R04Warn = []string{
}

var E68R04Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R04Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R04In(list []string, v string) bool {
	for _, x := range list { if E68R04Lower(x) == v { return true } }
	return false
}

// E68R04Classify 分类单个令牌。
func E68R04Classify(tok string) string {
	v := E68R04Lower(tok)
	switch {
	case E68R04In(E68R04Block, v): return E68R04ClassBlock
	case E68R04In(E68R04Warn, v): return E68R04ClassWarn
	case E68R04In(E68R04Allow, v): return E68R04ClassAllow
	default: return E68R04ClassUnknown
	}
}
