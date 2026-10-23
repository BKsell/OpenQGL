package main

// greekhomoglyphcatalogguard.go —— 希腊同形字母目录。
//
// 威胁模型：
//   希腊 ο/ν/α/ρ/υ 等与拉丁同形，用于同形域钓鱼，
//   命中同形字母应阻断，其余希腊码位需复核。纯字符查表，不用正则。

const (
	GHGClassBlock   = "block"
	GHGClassWarn    = "warn"
	GHGClassAllow   = "allow"
	GHGClassUnknown = "unknown"
)

var GHGBlock = []string{
	"U+038C",
	"U+0391",
	"U+0392",
	"U+0396",
	"U+0399",
	"U+039A",
	"U+039C",
	"U+039F",
	"U+03A1",
	"U+03A5",
	"U+03A7",
	"U+03B1",
	"U+03B6",
	"U+03B9",
	"U+03BA",
	"U+03BC",
	"U+03BD",
	"U+03BF",
	"U+03C1",
	"U+03C5",
	"U+03C7",
	"U+03CC",
}

var GHGWarn = []string{
	"U+0370",
	"U+0371",
	"U+0372",
	"U+0373",
	"U+0374",
	"U+0375",
	"U+0376",
	"U+0377",
	"U+0378",
	"U+0379",
	"U+037A",
	"U+037B",
	"U+037C",
	"U+037D",
	"U+037E",
	"U+037F",
	"U+0380",
	"U+0381",
	"U+0382",
	"U+0383",
	"U+0384",
	"U+0385",
	"U+0386",
	"U+0387",
	"U+0388",
	"U+0389",
	"U+038A",
	"U+038B",
	"U+038D",
	"U+038E",
	"U+038F",
	"U+0390",
	"U+0393",
	"U+0394",
	"U+0395",
	"U+0397",
	"U+0398",
	"U+039B",
	"U+039D",
	"U+039E",
	"U+03A0",
	"U+03A2",
	"U+03A3",
	"U+03A4",
	"U+03A6",
	"U+03A8",
	"U+03A9",
	"U+03AA",
	"U+03AB",
	"U+03AC",
	"U+03AD",
	"U+03AE",
	"U+03AF",
	"U+03B0",
	"U+03B2",
	"U+03B3",
	"U+03B4",
	"U+03B5",
	"U+03B7",
	"U+03B8",
	"U+03BB",
	"U+03BE",
	"U+03C0",
	"U+03C2",
	"U+03C3",
	"U+03C4",
	"U+03C6",
	"U+03C8",
	"U+03C9",
	"U+03CA",
	"U+03CB",
	"U+03CD",
	"U+03CE",
	"U+03CF",
	"U+03D0",
	"U+03D1",
	"U+03D2",
	"U+03D3",
	"U+03D4",
	"U+03D5",
	"U+03D6",
	"U+03D7",
	"U+03D8",
	"U+03D9",
	"U+03DA",
	"U+03DB",
	"U+03DC",
	"U+03DD",
	"U+03DE",
	"U+03DF",
	"U+03E0",
	"U+03E1",
	"U+03E2",
	"U+03E3",
	"U+03E4",
	"U+03E5",
	"U+03E6",
	"U+03E7",
	"U+03E8",
	"U+03E9",
	"U+03EA",
	"U+03EB",
	"U+03EC",
	"U+03ED",
	"U+03EE",
	"U+03EF",
	"U+03F0",
	"U+03F1",
	"U+03F2",
	"U+03F3",
	"U+03F4",
	"U+03F5",
	"U+03F6",
	"U+03F7",
	"U+03F8",
	"U+03F9",
	"U+03FA",
	"U+03FB",
	"U+03FC",
	"U+03FD",
	"U+03FE",
	"U+03FF",
}

var GHGAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func GHGLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func GHGIn(list []string, v string) bool {
	for _, x := range list { if GHGLower(x) == v { return true } }
	return false
}

// GHGClassify 分类单个令牌。
func GHGClassify(tok string) string {
	v := GHGLower(tok)
	switch {
	case GHGIn(GHGBlock, v): return GHGClassBlock
	case GHGIn(GHGWarn, v): return GHGClassWarn
	case GHGIn(GHGAllow, v): return GHGClassAllow
	default: return GHGClassUnknown
	}
}
