package main

// e70katakanaphoneticcatalogguard.go —— 片假名语音扩展码位目录。
//
// 威胁模型：
//   小字片假名扩展在标识符中无正当用途，可隐藏非 ASCII 数据，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T57ClassBlock   = "block"
	E70T57ClassWarn    = "warn"
	E70T57ClassAllow   = "allow"
	E70T57ClassUnknown = "unknown"
)

var E70T57Block = []string{
	"U+31F0",
	"U+31F1",
	"U+31F2",
	"U+31F3",
	"U+31F4",
	"U+31F5",
	"U+31F6",
	"U+31F7",
	"U+31F8",
	"U+31F9",
	"U+31FA",
	"U+31FB",
	"U+31FC",
	"U+31FD",
	"U+31FE",
	"U+31FF",
}

var E70T57Warn = []string{
}

var E70T57Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T57Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T57In(list []string, v string) bool {
	for _, x := range list { if E70T57Lower(x) == v { return true } }
	return false
}

// E70T57Classify 分类单个令牌。
func E70T57Classify(tok string) string {
	v := E70T57Lower(tok)
	switch {
	case E70T57In(E70T57Block, v): return E70T57ClassBlock
	case E70T57In(E70T57Warn, v): return E70T57ClassWarn
	case E70T57In(E70T57Allow, v): return E70T57ClassAllow
	default: return E70T57ClassUnknown
	}
}
