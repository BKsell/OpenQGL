package main

// e69mayanumeralscatalogguard.go —— 玛雅数字符号码位目录。
//
// 威胁模型：
//   玛雅数字等罕用数字形式在常规字段无正当用途，缺字体时不可见，
//   机器字段应拒绝。纯字符查表，不用正则。

const (
	E69U13ClassBlock   = "block"
	E69U13ClassWarn    = "warn"
	E69U13ClassAllow   = "allow"
	E69U13ClassUnknown = "unknown"
)

var E69U13Block = []string{
	"U+1D2E0",
	"U+1D2E1",
	"U+1D2E2",
	"U+1D2E3",
	"U+1D2E4",
	"U+1D2E5",
	"U+1D2E6",
	"U+1D2E7",
	"U+1D2E8",
	"U+1D2E9",
	"U+1D2EA",
	"U+1D2EB",
	"U+1D2EC",
	"U+1D2ED",
	"U+1D2EE",
	"U+1D2EF",
	"U+1D2F0",
	"U+1D2F1",
	"U+1D2F2",
	"U+1D2F3",
	"U+1D2F4",
	"U+1D2F5",
	"U+1D2F6",
	"U+1D2F7",
	"U+1D2F8",
	"U+1D2F9",
	"U+1D2FA",
	"U+1D2FB",
	"U+1D2FC",
	"U+1D2FD",
	"U+1D2FE",
	"U+1D2FF",
}

var E69U13Warn = []string{
}

var E69U13Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69U13Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69U13In(list []string, v string) bool {
	for _, x := range list { if E69U13Lower(x) == v { return true } }
	return false
}

// E69U13Classify 分类单个令牌。
func E69U13Classify(tok string) string {
	v := E69U13Lower(tok)
	switch {
	case E69U13In(E69U13Block, v): return E69U13ClassBlock
	case E69U13In(E69U13Warn, v): return E69U13ClassWarn
	case E69U13In(E69U13Allow, v): return E69U13ClassAllow
	default: return E69U13ClassUnknown
	}
}
