package main

// e70gothiccatalogguard.go —— 哥特文字平面目录。
//
// 威胁模型：
//   哥特字母与拉丁大写近似，混排可绕过同形检测，
//   标识符使用应拒绝。纯字符查表，不用正则。

const (
	E70U03ClassBlock   = "block"
	E70U03ClassWarn    = "warn"
	E70U03ClassAllow   = "allow"
	E70U03ClassUnknown = "unknown"
)

var E70U03Block = []string{
	"U+10330",
	"U+10331",
	"U+10332",
	"U+10333",
	"U+10334",
	"U+10335",
	"U+10336",
	"U+10337",
	"U+10338",
	"U+10339",
	"U+1033A",
	"U+1033B",
	"U+1033C",
	"U+1033D",
	"U+1033E",
	"U+1033F",
	"U+10340",
	"U+10341",
	"U+10342",
	"U+10343",
	"U+10344",
	"U+10345",
	"U+10346",
	"U+10347",
	"U+10348",
	"U+10349",
	"U+1034A",
	"U+1034B",
	"U+1034C",
	"U+1034D",
	"U+1034E",
	"U+1034F",
}

var E70U03Warn = []string{
}

var E70U03Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70U03Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70U03In(list []string, v string) bool {
	for _, x := range list { if E70U03Lower(x) == v { return true } }
	return false
}

// E70U03Classify 分类单个令牌。
func E70U03Classify(tok string) string {
	v := E70U03Lower(tok)
	switch {
	case E70U03In(E70U03Block, v): return E70U03ClassBlock
	case E70U03In(E70U03Warn, v): return E70U03ClassWarn
	case E70U03In(E70U03Allow, v): return E70U03ClassAllow
	default: return E70U03ClassUnknown
	}
}
