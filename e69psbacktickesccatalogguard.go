package main

// e69psbacktickesccatalogguard.go —— PowerShell 反引号转义字节目录。
//
// 威胁模型：
//   PowerShell 用反引号转义 引号/$/换行等特殊字符，剥离后还原危险字符，可混淆命令注入载荷，
//   危险字符转义应阻断。纯字符查表，不用正则。

const (
	E69PBTClassBlock   = "block"
	E69PBTClassWarn    = "warn"
	E69PBTClassAllow   = "allow"
	E69PBTClassUnknown = "unknown"
)

var E69PBTBlock = []string{
	"`0",
	"`a",
	"`b",
	"`n",
	"`r",
	"`\"",
	"`'",
	"``",
}

var E69PBTWarn = []string{
	"`t",
	"`$",
}

var E69PBTAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69PBTLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69PBTIn(list []string, v string) bool {
	for _, x := range list { if E69PBTLower(x) == v { return true } }
	return false
}

// E69PBTClassify 分类单个令牌。
func E69PBTClassify(tok string) string {
	v := E69PBTLower(tok)
	switch {
	case E69PBTIn(E69PBTBlock, v): return E69PBTClassBlock
	case E69PBTIn(E69PBTWarn, v): return E69PBTClassWarn
	case E69PBTIn(E69PBTAllow, v): return E69PBTClassAllow
	default: return E69PBTClassUnknown
	}
}
