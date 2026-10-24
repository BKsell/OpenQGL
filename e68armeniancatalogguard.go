package main

// e68armeniancatalogguard.go —— 亚美尼亚文字码位目录。
//
// 威胁模型：
//   亚美尼亚字母中存在与拉丁近似的字形，且非 ASCII 码位会改变规范化结果，
//   标识符/域名中应复核并转 punycode。纯字符查表，不用正则。

const (
	E68R00ClassBlock   = "block"
	E68R00ClassWarn    = "warn"
	E68R00ClassAllow   = "allow"
	E68R00ClassUnknown = "unknown"
)

var E68R00Block = []string{
}

var E68R00Warn = []string{
	"U+0530",
	"U+0531",
	"U+0532",
	"U+0533",
	"U+0534",
	"U+0535",
	"U+0536",
	"U+0537",
	"U+0538",
	"U+0539",
	"U+053A",
	"U+053B",
	"U+053C",
	"U+053D",
	"U+053E",
	"U+053F",
	"U+0540",
	"U+0541",
	"U+0542",
	"U+0543",
	"U+0544",
	"U+0545",
	"U+0546",
	"U+0547",
	"U+0548",
	"U+0549",
	"U+054A",
	"U+054B",
	"U+054C",
	"U+054D",
	"U+054E",
	"U+054F",
	"U+0550",
	"U+0551",
	"U+0552",
	"U+0553",
	"U+0554",
	"U+0555",
	"U+0556",
	"U+0557",
	"U+0558",
	"U+0559",
	"U+055A",
	"U+055B",
	"U+055C",
	"U+055D",
	"U+055E",
	"U+055F",
	"U+0560",
	"U+0561",
	"U+0562",
	"U+0563",
	"U+0564",
	"U+0565",
	"U+0566",
	"U+0567",
	"U+0568",
	"U+0569",
	"U+056A",
	"U+056B",
	"U+056C",
	"U+056D",
	"U+056E",
	"U+056F",
	"U+0570",
	"U+0571",
	"U+0572",
	"U+0573",
	"U+0574",
	"U+0575",
	"U+0576",
	"U+0577",
	"U+0578",
	"U+0579",
	"U+057A",
	"U+057B",
	"U+057C",
	"U+057D",
	"U+057E",
	"U+057F",
	"U+0580",
	"U+0581",
	"U+0582",
	"U+0583",
	"U+0584",
	"U+0585",
	"U+0586",
	"U+0587",
	"U+0588",
	"U+0589",
	"U+058A",
	"U+058B",
	"U+058C",
	"U+058D",
	"U+058E",
	"U+058F",
}

var E68R00Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E68R00Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E68R00In(list []string, v string) bool {
	for _, x := range list { if E68R00Lower(x) == v { return true } }
	return false
}

// E68R00Classify 分类单个令牌。
func E68R00Classify(tok string) string {
	v := E68R00Lower(tok)
	switch {
	case E68R00In(E68R00Block, v): return E68R00ClassBlock
	case E68R00In(E68R00Warn, v): return E68R00ClassWarn
	case E68R00In(E68R00Allow, v): return E68R00ClassAllow
	default: return E68R00ClassUnknown
	}
}
