package main

// e69transportmapcatalogguard.go —— 交通与地图补充平面目录。
//
// 威胁模型：
//   交通/地图表情符号不应进入机器字段，宽度不确定可挤出相邻内容，
//   结构化字段应拒绝。纯字符查表，不用正则。

const (
	E69U01ClassBlock   = "block"
	E69U01ClassWarn    = "warn"
	E69U01ClassAllow   = "allow"
	E69U01ClassUnknown = "unknown"
)

var E69U01Block = []string{
	"U+1F680",
	"U+1F681",
	"U+1F682",
	"U+1F683",
	"U+1F684",
	"U+1F685",
	"U+1F686",
	"U+1F687",
	"U+1F688",
	"U+1F689",
	"U+1F68A",
	"U+1F68B",
	"U+1F68C",
	"U+1F68D",
	"U+1F68E",
	"U+1F68F",
	"U+1F690",
	"U+1F691",
	"U+1F692",
	"U+1F693",
	"U+1F694",
	"U+1F695",
	"U+1F696",
	"U+1F697",
	"U+1F698",
	"U+1F699",
	"U+1F69A",
	"U+1F69B",
	"U+1F69C",
	"U+1F69D",
	"U+1F69E",
	"U+1F69F",
	"U+1F6A0",
	"U+1F6A1",
	"U+1F6A2",
	"U+1F6A3",
	"U+1F6A4",
	"U+1F6A5",
	"U+1F6A6",
	"U+1F6A7",
	"U+1F6A8",
	"U+1F6A9",
	"U+1F6AA",
	"U+1F6AB",
	"U+1F6AC",
	"U+1F6AD",
	"U+1F6AE",
	"U+1F6AF",
	"U+1F6B0",
	"U+1F6B1",
	"U+1F6B2",
	"U+1F6B3",
	"U+1F6B4",
	"U+1F6B5",
	"U+1F6B6",
	"U+1F6B7",
	"U+1F6B8",
	"U+1F6B9",
	"U+1F6BA",
	"U+1F6BB",
	"U+1F6BC",
	"U+1F6BD",
	"U+1F6BE",
	"U+1F6BF",
	"U+1F6C0",
	"U+1F6C1",
	"U+1F6C2",
	"U+1F6C3",
	"U+1F6C4",
	"U+1F6C5",
	"U+1F6C6",
	"U+1F6C7",
	"U+1F6C8",
	"U+1F6C9",
	"U+1F6CA",
	"U+1F6CB",
	"U+1F6CC",
	"U+1F6CD",
	"U+1F6CE",
	"U+1F6CF",
	"U+1F6D0",
	"U+1F6D1",
	"U+1F6D2",
	"U+1F6D3",
	"U+1F6D4",
	"U+1F6D5",
	"U+1F6D6",
	"U+1F6D7",
	"U+1F6D8",
	"U+1F6D9",
	"U+1F6DA",
	"U+1F6DB",
	"U+1F6DC",
	"U+1F6DD",
	"U+1F6DE",
	"U+1F6DF",
	"U+1F6E0",
	"U+1F6E1",
	"U+1F6E2",
	"U+1F6E3",
	"U+1F6E4",
	"U+1F6E5",
	"U+1F6E6",
	"U+1F6E7",
	"U+1F6E8",
	"U+1F6E9",
	"U+1F6EA",
	"U+1F6EB",
	"U+1F6EC",
	"U+1F6ED",
	"U+1F6EE",
	"U+1F6EF",
	"U+1F6F0",
	"U+1F6F1",
	"U+1F6F2",
	"U+1F6F3",
	"U+1F6F4",
	"U+1F6F5",
	"U+1F6F6",
	"U+1F6F7",
	"U+1F6F8",
	"U+1F6F9",
	"U+1F6FA",
	"U+1F6FB",
	"U+1F6FC",
	"U+1F6FD",
	"U+1F6FE",
	"U+1F6FF",
}

var E69U01Warn = []string{
}

var E69U01Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69U01Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69U01In(list []string, v string) bool {
	for _, x := range list { if E69U01Lower(x) == v { return true } }
	return false
}

// E69U01Classify 分类单个令牌。
func E69U01Classify(tok string) string {
	v := E69U01Lower(tok)
	switch {
	case E69U01In(E69U01Block, v): return E69U01ClassBlock
	case E69U01In(E69U01Warn, v): return E69U01ClassWarn
	case E69U01In(E69U01Allow, v): return E69U01ClassAllow
	default: return E69U01ClassUnknown
	}
}
