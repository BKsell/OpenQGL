package main

// e70olditaliccatalogguard.go —— 古意大利文字平面目录。
//
// 威胁模型：
//   古意大利字母与拉丁大写近似且罕用，可做视觉仿冒，
//   标识符使用应拒绝。纯字符查表，不用正则。

const (
	E70U02ClassBlock   = "block"
	E70U02ClassWarn    = "warn"
	E70U02ClassAllow   = "allow"
	E70U02ClassUnknown = "unknown"
)

var E70U02Block = []string{
	"U+10300",
	"U+10301",
	"U+10302",
	"U+10303",
	"U+10304",
	"U+10305",
	"U+10306",
	"U+10307",
	"U+10308",
	"U+10309",
	"U+1030A",
	"U+1030B",
	"U+1030C",
	"U+1030D",
	"U+1030E",
	"U+1030F",
	"U+10310",
	"U+10311",
	"U+10312",
	"U+10313",
	"U+10314",
	"U+10315",
	"U+10316",
	"U+10317",
	"U+10318",
	"U+10319",
	"U+1031A",
	"U+1031B",
	"U+1031C",
	"U+1031D",
	"U+1031E",
	"U+1031F",
	"U+10320",
	"U+10321",
	"U+10322",
	"U+10323",
	"U+10324",
	"U+10325",
	"U+10326",
	"U+10327",
	"U+10328",
	"U+10329",
	"U+1032A",
	"U+1032B",
	"U+1032C",
	"U+1032D",
	"U+1032E",
	"U+1032F",
}

var E70U02Warn = []string{
}

var E70U02Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70U02Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70U02In(list []string, v string) bool {
	for _, x := range list { if E70U02Lower(x) == v { return true } }
	return false
}

// E70U02Classify 分类单个令牌。
func E70U02Classify(tok string) string {
	v := E70U02Lower(tok)
	switch {
	case E70U02In(E70U02Block, v): return E70U02ClassBlock
	case E70U02In(E70U02Warn, v): return E70U02ClassWarn
	case E70U02In(E70U02Allow, v): return E70U02ClassAllow
	default: return E70U02ClassUnknown
	}
}
