package main

// e70cypriotsyllabarycatalogguard.go —— 塞浦路斯音节文字目录。
//
// 威胁模型：
//   塞浦路斯音节文字为古文字，机器字段无任何正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70U08ClassBlock   = "block"
	E70U08ClassWarn    = "warn"
	E70U08ClassAllow   = "allow"
	E70U08ClassUnknown = "unknown"
)

var E70U08Block = []string{
	"U+10800",
	"U+10801",
	"U+10802",
	"U+10803",
	"U+10804",
	"U+10805",
	"U+10806",
	"U+10807",
	"U+10808",
	"U+10809",
	"U+1080A",
	"U+1080B",
	"U+1080C",
	"U+1080D",
	"U+1080E",
	"U+1080F",
	"U+10810",
	"U+10811",
	"U+10812",
	"U+10813",
	"U+10814",
	"U+10815",
	"U+10816",
	"U+10817",
	"U+10818",
	"U+10819",
	"U+1081A",
	"U+1081B",
	"U+1081C",
	"U+1081D",
	"U+1081E",
	"U+1081F",
	"U+10820",
	"U+10821",
	"U+10822",
	"U+10823",
	"U+10824",
	"U+10825",
	"U+10826",
	"U+10827",
	"U+10828",
	"U+10829",
	"U+1082A",
	"U+1082B",
	"U+1082C",
	"U+1082D",
	"U+1082E",
	"U+1082F",
	"U+10830",
	"U+10831",
	"U+10832",
	"U+10833",
	"U+10834",
	"U+10835",
	"U+10836",
	"U+10837",
	"U+10838",
	"U+10839",
	"U+1083A",
	"U+1083B",
	"U+1083C",
	"U+1083D",
	"U+1083E",
	"U+1083F",
}

var E70U08Warn = []string{
}

var E70U08Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70U08Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70U08In(list []string, v string) bool {
	for _, x := range list { if E70U08Lower(x) == v { return true } }
	return false
}

// E70U08Classify 分类单个令牌。
func E70U08Classify(tok string) string {
	v := E70U08Lower(tok)
	switch {
	case E70U08In(E70U08Block, v): return E70U08ClassBlock
	case E70U08In(E70U08Warn, v): return E70U08ClassWarn
	case E70U08In(E70U08Allow, v): return E70U08ClassAllow
	default: return E70U08ClassUnknown
	}
}
