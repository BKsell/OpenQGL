package main

// e69cnamedescapescatalogguard.go —— C 风格命名转义字节目录。
//
// 威胁模型：
//   \0 \n \r \\ \" 等命名转义在源码/配置中还原控制符与引号，可隐藏注入分隔符，
//   危险字节命名转义应阻断。纯字符查表，不用正则。

const (
	E69CNEClassBlock   = "block"
	E69CNEClassWarn    = "warn"
	E69CNEClassAllow   = "allow"
	E69CNEClassUnknown = "unknown"
)

var E69CNEBlock = []string{
	"\\0",
	"\\a",
	"\\b",
	"\\n",
	"\\v",
	"\\f",
	"\\r",
	"\\\"",
	"\\'",
	"\\\\",
}

var E69CNEWarn = []string{
	"\\t",
}

var E69CNEAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69CNELower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69CNEIn(list []string, v string) bool {
	for _, x := range list { if E69CNELower(x) == v { return true } }
	return false
}

// E69CNEClassify 分类单个令牌。
func E69CNEClassify(tok string) string {
	v := E69CNELower(tok)
	switch {
	case E69CNEIn(E69CNEBlock, v): return E69CNEClassBlock
	case E69CNEIn(E69CNEWarn, v): return E69CNEClassWarn
	case E69CNEIn(E69CNEAllow, v): return E69CNEClassAllow
	default: return E69CNEClassUnknown
	}
}
