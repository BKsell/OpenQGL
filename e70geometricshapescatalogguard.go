package main

// e70geometricshapescatalogguard.go —— 几何形状码位目录。
//
// 威胁模型：
//   几何形状符号在机器字段无正当用途，可用于界面仿冒，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T47ClassBlock   = "block"
	E70T47ClassWarn    = "warn"
	E70T47ClassAllow   = "allow"
	E70T47ClassUnknown = "unknown"
)

var E70T47Block = []string{
	"U+25A0",
	"U+25A1",
	"U+25A2",
	"U+25A3",
	"U+25A4",
	"U+25A5",
	"U+25A6",
	"U+25A7",
	"U+25A8",
	"U+25A9",
	"U+25AA",
	"U+25AB",
	"U+25AC",
	"U+25AD",
	"U+25AE",
	"U+25AF",
	"U+25B0",
	"U+25B1",
	"U+25B2",
	"U+25B3",
	"U+25B4",
	"U+25B5",
	"U+25B6",
	"U+25B7",
	"U+25B8",
	"U+25B9",
	"U+25BA",
	"U+25BB",
	"U+25BC",
	"U+25BD",
	"U+25BE",
	"U+25BF",
	"U+25C0",
	"U+25C1",
	"U+25C2",
	"U+25C3",
	"U+25C4",
	"U+25C5",
	"U+25C6",
	"U+25C7",
	"U+25C8",
	"U+25C9",
	"U+25CA",
	"U+25CB",
	"U+25CC",
	"U+25CD",
	"U+25CE",
	"U+25CF",
	"U+25D0",
	"U+25D1",
	"U+25D2",
	"U+25D3",
	"U+25D4",
	"U+25D5",
	"U+25D6",
	"U+25D7",
	"U+25D8",
	"U+25D9",
	"U+25DA",
	"U+25DB",
	"U+25DC",
	"U+25DD",
	"U+25DE",
	"U+25DF",
	"U+25E0",
	"U+25E1",
	"U+25E2",
	"U+25E3",
	"U+25E4",
	"U+25E5",
	"U+25E6",
	"U+25E7",
	"U+25E8",
	"U+25E9",
	"U+25EA",
	"U+25EB",
	"U+25EC",
	"U+25ED",
	"U+25EE",
	"U+25EF",
	"U+25F0",
	"U+25F1",
	"U+25F2",
	"U+25F3",
	"U+25F4",
	"U+25F5",
	"U+25F6",
	"U+25F7",
	"U+25F8",
	"U+25F9",
	"U+25FA",
	"U+25FB",
	"U+25FC",
	"U+25FD",
	"U+25FE",
	"U+25FF",
}

var E70T47Warn = []string{
}

var E70T47Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T47Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T47In(list []string, v string) bool {
	for _, x := range list { if E70T47Lower(x) == v { return true } }
	return false
}

// E70T47Classify 分类单个令牌。
func E70T47Classify(tok string) string {
	v := E70T47Lower(tok)
	switch {
	case E70T47In(E70T47Block, v): return E70T47ClassBlock
	case E70T47In(E70T47Warn, v): return E70T47ClassWarn
	case E70T47In(E70T47Allow, v): return E70T47ClassAllow
	default: return E70T47ClassUnknown
	}
}
