package main

// e68geometriccatalogguard.go —— 几何形状码位目录。
//
// 威胁模型：
//   几何符号可仿冒项目符号与状态标记，
//   结构化解析应按码点而非字形。纯字符查表，不用正则。

const (
	E68R33ClassBlock   = "block"
	E68R33ClassWarn    = "warn"
	E68R33ClassAllow   = "allow"
	E68R33ClassUnknown = "unknown"
)

var E68R33Block = []string{
}

var E68R33Warn = []string{
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

var E68R33Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R33Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R33In(list []string, v string) bool {
	for _, x := range list { if E68R33Lower(x) == v { return true } }
	return false
}

// E68R33Classify 分类单个令牌。
func E68R33Classify(tok string) string {
	v := E68R33Lower(tok)
	switch {
	case E68R33In(E68R33Block, v): return E68R33ClassBlock
	case E68R33In(E68R33Warn, v): return E68R33ClassWarn
	case E68R33In(E68R33Allow, v): return E68R33ClassAllow
	default: return E68R33ClassUnknown
	}
}
