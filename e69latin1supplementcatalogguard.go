package main

// e69latin1supplementcatalogguard.go —— Latin-1 补充码位目录。
//
// 威胁模型：
//   该块含 C1 控制符、不换行空格 U+00A0 与软连字符 U+00AD，可做间隔欺骗与断字隐藏，
//   应 NFKC 归一化并剥离控制符。纯字符查表，不用正则。

const (
	E69T00ClassBlock   = "block"
	E69T00ClassWarn    = "warn"
	E69T00ClassAllow   = "allow"
	E69T00ClassUnknown = "unknown"
)

var E69T00Block = []string{
}

var E69T00Warn = []string{
	"U+0080",
	"U+0081",
	"U+0082",
	"U+0083",
	"U+0084",
	"U+0085",
	"U+0086",
	"U+0087",
	"U+0088",
	"U+0089",
	"U+008A",
	"U+008B",
	"U+008C",
	"U+008D",
	"U+008E",
	"U+008F",
	"U+0090",
	"U+0091",
	"U+0092",
	"U+0093",
	"U+0094",
	"U+0095",
	"U+0096",
	"U+0097",
	"U+0098",
	"U+0099",
	"U+009A",
	"U+009B",
	"U+009C",
	"U+009D",
	"U+009E",
	"U+009F",
	"U+00A0",
	"U+00A1",
	"U+00A2",
	"U+00A3",
	"U+00A4",
	"U+00A5",
	"U+00A6",
	"U+00A7",
	"U+00A8",
	"U+00A9",
	"U+00AA",
	"U+00AB",
	"U+00AC",
	"U+00AD",
	"U+00AE",
	"U+00AF",
	"U+00B0",
	"U+00B1",
	"U+00B2",
	"U+00B3",
	"U+00B4",
	"U+00B5",
	"U+00B6",
	"U+00B7",
	"U+00B8",
	"U+00B9",
	"U+00BA",
	"U+00BB",
	"U+00BC",
	"U+00BD",
	"U+00BE",
	"U+00BF",
	"U+00C0",
	"U+00C1",
	"U+00C2",
	"U+00C3",
	"U+00C4",
	"U+00C5",
	"U+00C6",
	"U+00C7",
	"U+00C8",
	"U+00C9",
	"U+00CA",
	"U+00CB",
	"U+00CC",
	"U+00CD",
	"U+00CE",
	"U+00CF",
	"U+00D0",
	"U+00D1",
	"U+00D2",
	"U+00D3",
	"U+00D4",
	"U+00D5",
	"U+00D6",
	"U+00D7",
	"U+00D8",
	"U+00D9",
	"U+00DA",
	"U+00DB",
	"U+00DC",
	"U+00DD",
	"U+00DE",
	"U+00DF",
	"U+00E0",
	"U+00E1",
	"U+00E2",
	"U+00E3",
	"U+00E4",
	"U+00E5",
	"U+00E6",
	"U+00E7",
	"U+00E8",
	"U+00E9",
	"U+00EA",
	"U+00EB",
	"U+00EC",
	"U+00ED",
	"U+00EE",
	"U+00EF",
	"U+00F0",
	"U+00F1",
	"U+00F2",
	"U+00F3",
	"U+00F4",
	"U+00F5",
	"U+00F6",
	"U+00F7",
	"U+00F8",
	"U+00F9",
	"U+00FA",
	"U+00FB",
	"U+00FC",
	"U+00FD",
	"U+00FE",
	"U+00FF",
}

var E69T00Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69T00Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69T00In(list []string, v string) bool {
	for _, x := range list { if E69T00Lower(x) == v { return true } }
	return false
}

// E69T00Classify 分类单个令牌。
func E69T00Classify(tok string) string {
	v := E69T00Lower(tok)
	switch {
	case E69T00In(E69T00Block, v): return E69T00ClassBlock
	case E69T00In(E69T00Warn, v): return E69T00ClassWarn
	case E69T00In(E69T00Allow, v): return E69T00ClassAllow
	default: return E69T00ClassUnknown
	}
}
