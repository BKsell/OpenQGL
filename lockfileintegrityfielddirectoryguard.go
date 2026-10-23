package main

// lockfileintegrityfielddirectoryguard.go —— 锁文件完整性字段目录。
//
// 威胁模型：
//   锁文件 integrity 用 sha1、resolved 指向 http 或未知 registry 都不可信，
//   应 sha512 + 官方源。纯字符查表，不用正则。

const (
	LIKClassBlock   = "block"
	LIKClassWarn    = "warn"
	LIKClassAllow   = "allow"
	LIKClassUnknown = "unknown"
)

var LIKBlock = []string{
	"integrity-sha1",
	"resolved-http",
	"unknown-registry",
	"no-integrity",
}

var LIKWarn = []string{
	"http-redirect",
}

var LIKAllow = []string{
	"sha512",
	"official-registry",
}

func LIKLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func LIKIn(list []string, v string) bool {
	for _, x := range list { if LIKLower(x) == v { return true } }
	return false
}

// LIKClassify 分类单个令牌。
func LIKClassify(tok string) string {
	v := LIKLower(tok)
	switch {
	case LIKIn(LIKBlock, v): return LIKClassBlock
	case LIKIn(LIKWarn, v): return LIKClassWarn
	case LIKIn(LIKAllow, v): return LIKClassAllow
	default: return LIKClassUnknown
	}
}
