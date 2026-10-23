package main

// toctoucheckracedirectoryguard.go —— TOCTOU 检查/使用竞争目录。
//
// 威胁模型：
//   access() 后再 open()、stat 后使用、跟随符号链接在两步间可被替换，
//   应 openat + O_NOFOLLOW 一次性校验。纯字符查表，不用正则。

const (
	TOUClassBlock   = "block"
	TOUClassWarn    = "warn"
	TOUClassAllow   = "allow"
	TOUClassUnknown = "unknown"
)

var TOUBlock = []string{
	"access-then-open",
	"stat-then-use",
	"symlink-follow",
	"check-then-use",
}

var TOUWarn = []string{
	"lstat-only",
}

var TOUAllow = []string{
	"openat-nofollow",
	"fd-reuse",
}

func TOULower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TOUIn(list []string, v string) bool {
	for _, x := range list { if TOULower(x) == v { return true } }
	return false
}

// TOUClassify 分类单个令牌。
func TOUClassify(tok string) string {
	v := TOULower(tok)
	switch {
	case TOUIn(TOUBlock, v): return TOUClassBlock
	case TOUIn(TOUWarn, v): return TOUClassWarn
	case TOUIn(TOUAllow, v): return TOUClassAllow
	default: return TOUClassUnknown
	}
}
