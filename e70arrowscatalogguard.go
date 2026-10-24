package main

// e70arrowscatalogguard.go —— 箭头符号码位目录。
//
// 威胁模型：
//   箭头符号在标识符/路径/命令中无正当用途，可用于界面仿冒，
//   机器字段应拒绝。纯字符查表，不用正则。

const (
	E70T40ClassBlock   = "block"
	E70T40ClassWarn    = "warn"
	E70T40ClassAllow   = "allow"
	E70T40ClassUnknown = "unknown"
)

var E70T40Block = []string{
	"U+2190",
	"U+2191",
	"U+2192",
	"U+2193",
	"U+2194",
	"U+2195",
	"U+2196",
	"U+2197",
	"U+2198",
	"U+2199",
	"U+219A",
	"U+219B",
	"U+219C",
	"U+219D",
	"U+219E",
	"U+219F",
	"U+21A0",
	"U+21A1",
	"U+21A2",
	"U+21A3",
	"U+21A4",
	"U+21A5",
	"U+21A6",
	"U+21A7",
	"U+21A8",
	"U+21A9",
	"U+21AA",
	"U+21AB",
	"U+21AC",
	"U+21AD",
	"U+21AE",
	"U+21AF",
	"U+21B0",
	"U+21B1",
	"U+21B2",
	"U+21B3",
	"U+21B4",
	"U+21B5",
	"U+21B6",
	"U+21B7",
	"U+21B8",
	"U+21B9",
	"U+21BA",
	"U+21BB",
	"U+21BC",
	"U+21BD",
	"U+21BE",
	"U+21BF",
	"U+21C0",
	"U+21C1",
	"U+21C2",
	"U+21C3",
	"U+21C4",
	"U+21C5",
	"U+21C6",
	"U+21C7",
	"U+21C8",
	"U+21C9",
	"U+21CA",
	"U+21CB",
	"U+21CC",
	"U+21CD",
	"U+21CE",
	"U+21CF",
	"U+21D0",
	"U+21D1",
	"U+21D2",
	"U+21D3",
	"U+21D4",
	"U+21D5",
	"U+21D6",
	"U+21D7",
	"U+21D8",
	"U+21D9",
	"U+21DA",
	"U+21DB",
	"U+21DC",
	"U+21DD",
	"U+21DE",
	"U+21DF",
	"U+21E0",
	"U+21E1",
	"U+21E2",
	"U+21E3",
	"U+21E4",
	"U+21E5",
	"U+21E6",
	"U+21E7",
	"U+21E8",
	"U+21E9",
	"U+21EA",
	"U+21EB",
	"U+21EC",
	"U+21ED",
	"U+21EE",
	"U+21EF",
	"U+21F0",
	"U+21F1",
	"U+21F2",
	"U+21F3",
	"U+21F4",
	"U+21F5",
	"U+21F6",
	"U+21F7",
	"U+21F8",
	"U+21F9",
	"U+21FA",
	"U+21FB",
	"U+21FC",
	"U+21FD",
	"U+21FE",
	"U+21FF",
}

var E70T40Warn = []string{
}

var E70T40Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T40Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T40In(list []string, v string) bool {
	for _, x := range list { if E70T40Lower(x) == v { return true } }
	return false
}

// E70T40Classify 分类单个令牌。
func E70T40Classify(tok string) string {
	v := E70T40Lower(tok)
	switch {
	case E70T40In(E70T40Block, v): return E70T40ClassBlock
	case E70T40In(E70T40Warn, v): return E70T40ClassWarn
	case E70T40In(E70T40Allow, v): return E70T40ClassAllow
	default: return E70T40ClassUnknown
	}
}
