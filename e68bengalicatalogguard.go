package main

// e68bengalicatalogguard.go —— 孟加拉文字码位目录。
//
// 威胁模型：
//   孟加拉文含大量组合附加符，可视化与码位序列不一致，
//   应先规范化再判定。纯字符查表，不用正则。

const (
	E68R06ClassBlock   = "block"
	E68R06ClassWarn    = "warn"
	E68R06ClassAllow   = "allow"
	E68R06ClassUnknown = "unknown"
)

var E68R06Block = []string{
}

var E68R06Warn = []string{
	"U+0980",
	"U+0981",
	"U+0982",
	"U+0983",
	"U+0984",
	"U+0985",
	"U+0986",
	"U+0987",
	"U+0988",
	"U+0989",
	"U+098A",
	"U+098B",
	"U+098C",
	"U+098D",
	"U+098E",
	"U+098F",
	"U+0990",
	"U+0991",
	"U+0992",
	"U+0993",
	"U+0994",
	"U+0995",
	"U+0996",
	"U+0997",
	"U+0998",
	"U+0999",
	"U+099A",
	"U+099B",
	"U+099C",
	"U+099D",
	"U+099E",
	"U+099F",
	"U+09A0",
	"U+09A1",
	"U+09A2",
	"U+09A3",
	"U+09A4",
	"U+09A5",
	"U+09A6",
	"U+09A7",
	"U+09A8",
	"U+09A9",
	"U+09AA",
	"U+09AB",
	"U+09AC",
	"U+09AD",
	"U+09AE",
	"U+09AF",
	"U+09B0",
	"U+09B1",
	"U+09B2",
	"U+09B3",
	"U+09B4",
	"U+09B5",
	"U+09B6",
	"U+09B7",
	"U+09B8",
	"U+09B9",
	"U+09BA",
	"U+09BB",
	"U+09BC",
	"U+09BD",
	"U+09BE",
	"U+09BF",
	"U+09C0",
	"U+09C1",
	"U+09C2",
	"U+09C3",
	"U+09C4",
	"U+09C5",
	"U+09C6",
	"U+09C7",
	"U+09C8",
	"U+09C9",
	"U+09CA",
	"U+09CB",
	"U+09CC",
	"U+09CD",
	"U+09CE",
	"U+09CF",
	"U+09D0",
	"U+09D1",
	"U+09D2",
	"U+09D3",
	"U+09D4",
	"U+09D5",
	"U+09D6",
	"U+09D7",
	"U+09D8",
	"U+09D9",
	"U+09DA",
	"U+09DB",
	"U+09DC",
	"U+09DD",
	"U+09DE",
	"U+09DF",
	"U+09E0",
	"U+09E1",
	"U+09E2",
	"U+09E3",
	"U+09E4",
	"U+09E5",
	"U+09E6",
	"U+09E7",
	"U+09E8",
	"U+09E9",
	"U+09EA",
	"U+09EB",
	"U+09EC",
	"U+09ED",
	"U+09EE",
	"U+09EF",
	"U+09F0",
	"U+09F1",
	"U+09F2",
	"U+09F3",
	"U+09F4",
	"U+09F5",
	"U+09F6",
	"U+09F7",
	"U+09F8",
	"U+09F9",
	"U+09FA",
	"U+09FB",
	"U+09FC",
	"U+09FD",
	"U+09FE",
	"U+09FF",
}

var E68R06Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R06Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R06In(list []string, v string) bool {
	for _, x := range list { if E68R06Lower(x) == v { return true } }
	return false
}

// E68R06Classify 分类单个令牌。
func E68R06Classify(tok string) string {
	v := E68R06Lower(tok)
	switch {
	case E68R06In(E68R06Block, v): return E68R06ClassBlock
	case E68R06In(E68R06Warn, v): return E68R06ClassWarn
	case E68R06In(E68R06Allow, v): return E68R06ClassAllow
	default: return E68R06ClassUnknown
	}
}
