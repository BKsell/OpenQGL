package main

// e69yijinghexagramcatalogguard.go —— 易经卦象符号码位目录。
//
// 威胁模型：
//   易经卦象符号在任何文本机器字段都无正当用途，缺字体时不可见，
//   应拒绝。纯字符查表，不用正则。

const (
	E69T31ClassBlock   = "block"
	E69T31ClassWarn    = "warn"
	E69T31ClassAllow   = "allow"
	E69T31ClassUnknown = "unknown"
)

var E69T31Block = []string{
	"U+4DC0",
	"U+4DC1",
	"U+4DC2",
	"U+4DC3",
	"U+4DC4",
	"U+4DC5",
	"U+4DC6",
	"U+4DC7",
	"U+4DC8",
	"U+4DC9",
	"U+4DCA",
	"U+4DCB",
	"U+4DCC",
	"U+4DCD",
	"U+4DCE",
	"U+4DCF",
	"U+4DD0",
	"U+4DD1",
	"U+4DD2",
	"U+4DD3",
	"U+4DD4",
	"U+4DD5",
	"U+4DD6",
	"U+4DD7",
	"U+4DD8",
	"U+4DD9",
	"U+4DDA",
	"U+4DDB",
	"U+4DDC",
	"U+4DDD",
	"U+4DDE",
	"U+4DDF",
	"U+4DE0",
	"U+4DE1",
	"U+4DE2",
	"U+4DE3",
	"U+4DE4",
	"U+4DE5",
	"U+4DE6",
	"U+4DE7",
	"U+4DE8",
	"U+4DE9",
	"U+4DEA",
	"U+4DEB",
	"U+4DEC",
	"U+4DED",
	"U+4DEE",
	"U+4DEF",
	"U+4DF0",
	"U+4DF1",
	"U+4DF2",
	"U+4DF3",
	"U+4DF4",
	"U+4DF5",
	"U+4DF6",
	"U+4DF7",
	"U+4DF8",
	"U+4DF9",
	"U+4DFA",
	"U+4DFB",
	"U+4DFC",
	"U+4DFD",
	"U+4DFE",
	"U+4DFF",
}

var E69T31Warn = []string{
}

var E69T31Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T31Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T31In(list []string, v string) bool {
	for _, x := range list { if E69T31Lower(x) == v { return true } }
	return false
}

// E69T31Classify 分类单个令牌。
func E69T31Classify(tok string) string {
	v := E69T31Lower(tok)
	switch {
	case E69T31In(E69T31Block, v): return E69T31ClassBlock
	case E69T31In(E69T31Warn, v): return E69T31ClassWarn
	case E69T31In(E69T31Allow, v): return E69T31ClassAllow
	default: return E69T31ClassUnknown
	}
}
