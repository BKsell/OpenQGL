package main

// e69regionalindicatorscatalogguard.go —— 区域指示符码位目录。
//
// 威胁模型：
//   区域指示符两两组合成国旗 emoji，单字符无意义但可注入造成终端宽度与组合异常，
//   标识符/命令字段应拒绝。纯字符查表，不用正则。

const (
	E69U04ClassBlock   = "block"
	E69U04ClassWarn    = "warn"
	E69U04ClassAllow   = "allow"
	E69U04ClassUnknown = "unknown"
)

var E69U04Block = []string{
}

var E69U04Warn = []string{
	"U+1F1E6",
	"U+1F1E7",
	"U+1F1E8",
	"U+1F1E9",
	"U+1F1EA",
	"U+1F1EB",
	"U+1F1EC",
	"U+1F1ED",
	"U+1F1EE",
	"U+1F1EF",
	"U+1F1F0",
	"U+1F1F1",
	"U+1F1F2",
	"U+1F1F3",
	"U+1F1F4",
	"U+1F1F5",
	"U+1F1F6",
	"U+1F1F7",
	"U+1F1F8",
	"U+1F1F9",
	"U+1F1FA",
	"U+1F1FB",
	"U+1F1FC",
	"U+1F1FD",
	"U+1F1FE",
	"U+1F1FF",
}

var E69U04Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69U04Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69U04In(list []string, v string) bool {
	for _, x := range list { if E69U04Lower(x) == v { return true } }
	return false
}

// E69U04Classify 分类单个令牌。
func E69U04Classify(tok string) string {
	v := E69U04Lower(tok)
	switch {
	case E69U04In(E69U04Block, v): return E69U04ClassBlock
	case E69U04In(E69U04Warn, v): return E69U04ClassWarn
	case E69U04In(E69U04Allow, v): return E69U04ClassAllow
	default: return E69U04ClassUnknown
	}
}
