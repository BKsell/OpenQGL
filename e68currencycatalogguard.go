package main

// e68currencycatalogguard.go —— 货币符号码位目录。
//
// 威胁模型：
//   非标准货币符号常被用于钓鱼界面与财务文本伪造，
//   展示与解析应按码点而非字形。纯字符查表，不用正则。

const (
	E68R23ClassBlock   = "block"
	E68R23ClassWarn    = "warn"
	E68R23ClassAllow   = "allow"
	E68R23ClassUnknown = "unknown"
)

var E68R23Block = []string{
}

var E68R23Warn = []string{
	"U+20A0",
	"U+20A1",
	"U+20A2",
	"U+20A3",
	"U+20A4",
	"U+20A5",
	"U+20A6",
	"U+20A7",
	"U+20A8",
	"U+20A9",
	"U+20AA",
	"U+20AB",
	"U+20AC",
	"U+20AD",
	"U+20AE",
	"U+20AF",
	"U+20B0",
	"U+20B1",
	"U+20B2",
	"U+20B3",
	"U+20B4",
	"U+20B5",
	"U+20B6",
	"U+20B7",
	"U+20B8",
	"U+20B9",
	"U+20BA",
	"U+20BB",
	"U+20BC",
	"U+20BD",
	"U+20BE",
	"U+20BF",
	"U+20C0",
	"U+20C1",
	"U+20C2",
	"U+20C3",
	"U+20C4",
	"U+20C5",
	"U+20C6",
	"U+20C7",
	"U+20C8",
	"U+20C9",
	"U+20CA",
	"U+20CB",
	"U+20CC",
	"U+20CD",
	"U+20CE",
	"U+20CF",
}

var E68R23Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R23Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R23In(list []string, v string) bool {
	for _, x := range list { if E68R23Lower(x) == v { return true } }
	return false
}

// E68R23Classify 分类单个令牌。
func E68R23Classify(tok string) string {
	v := E68R23Lower(tok)
	switch {
	case E68R23In(E68R23Block, v): return E68R23ClassBlock
	case E68R23In(E68R23Warn, v): return E68R23ClassWarn
	case E68R23In(E68R23Allow, v): return E68R23ClassAllow
	default: return E68R23ClassUnknown
	}
}
