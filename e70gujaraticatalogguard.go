package main

// e70gujaraticatalogguard.go —— 古吉拉特文字码位目录。
//
// 威胁模型：
//   古吉拉特文在机器标识符中无正当用途，渲染依赖字体，
//   应直接拒绝。纯字符查表，不用正则。

const (
	E70T12ClassBlock   = "block"
	E70T12ClassWarn    = "warn"
	E70T12ClassAllow   = "allow"
	E70T12ClassUnknown = "unknown"
)

var E70T12Block = []string{
	"U+0A80",
	"U+0A81",
	"U+0A82",
	"U+0A83",
	"U+0A84",
	"U+0A85",
	"U+0A86",
	"U+0A87",
	"U+0A88",
	"U+0A89",
	"U+0A8A",
	"U+0A8B",
	"U+0A8C",
	"U+0A8D",
	"U+0A8E",
	"U+0A8F",
	"U+0A90",
	"U+0A91",
	"U+0A92",
	"U+0A93",
	"U+0A94",
	"U+0A95",
	"U+0A96",
	"U+0A97",
	"U+0A98",
	"U+0A99",
	"U+0A9A",
	"U+0A9B",
	"U+0A9C",
	"U+0A9D",
	"U+0A9E",
	"U+0A9F",
	"U+0AA0",
	"U+0AA1",
	"U+0AA2",
	"U+0AA3",
	"U+0AA4",
	"U+0AA5",
	"U+0AA6",
	"U+0AA7",
	"U+0AA8",
	"U+0AA9",
	"U+0AAA",
	"U+0AAB",
	"U+0AAC",
	"U+0AAD",
	"U+0AAE",
	"U+0AAF",
	"U+0AB0",
	"U+0AB1",
	"U+0AB2",
	"U+0AB3",
	"U+0AB4",
	"U+0AB5",
	"U+0AB6",
	"U+0AB7",
	"U+0AB8",
	"U+0AB9",
	"U+0ABA",
	"U+0ABB",
	"U+0ABC",
	"U+0ABD",
	"U+0ABE",
	"U+0ABF",
	"U+0AC0",
	"U+0AC1",
	"U+0AC2",
	"U+0AC3",
	"U+0AC4",
	"U+0AC5",
	"U+0AC6",
	"U+0AC7",
	"U+0AC8",
	"U+0AC9",
	"U+0ACA",
	"U+0ACB",
	"U+0ACC",
	"U+0ACD",
	"U+0ACE",
	"U+0ACF",
	"U+0AD0",
	"U+0AD1",
	"U+0AD2",
	"U+0AD3",
	"U+0AD4",
	"U+0AD5",
	"U+0AD6",
	"U+0AD7",
	"U+0AD8",
	"U+0AD9",
	"U+0ADA",
	"U+0ADB",
	"U+0ADC",
	"U+0ADD",
	"U+0ADE",
	"U+0ADF",
	"U+0AE0",
	"U+0AE1",
	"U+0AE2",
	"U+0AE3",
	"U+0AE4",
	"U+0AE5",
	"U+0AE6",
	"U+0AE7",
	"U+0AE8",
	"U+0AE9",
	"U+0AEA",
	"U+0AEB",
	"U+0AEC",
	"U+0AED",
	"U+0AEE",
	"U+0AEF",
	"U+0AF0",
	"U+0AF1",
	"U+0AF2",
	"U+0AF3",
	"U+0AF4",
	"U+0AF5",
	"U+0AF6",
	"U+0AF7",
	"U+0AF8",
	"U+0AF9",
	"U+0AFA",
	"U+0AFB",
	"U+0AFC",
	"U+0AFD",
	"U+0AFE",
	"U+0AFF",
}

var E70T12Warn = []string{
}

var E70T12Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T12Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T12In(list []string, v string) bool {
	for _, x := range list { if E70T12Lower(x) == v { return true } }
	return false
}

// E70T12Classify 分类单个令牌。
func E70T12Classify(tok string) string {
	v := E70T12Lower(tok)
	switch {
	case E70T12In(E70T12Block, v): return E70T12ClassBlock
	case E70T12In(E70T12Warn, v): return E70T12ClassWarn
	case E70T12In(E70T12Allow, v): return E70T12ClassAllow
	default: return E70T12ClassUnknown
	}
}
