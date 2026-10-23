package main

// snakeyamlconstructordirectoryguard.go —— SnakeYAML 危险类型标签目录。
//
// 威胁模型：
//   !! 全局标签可实例化任意 Java 类，javax.script/com.sun 等标签导致代码执行，
//   应使用 SafeConstructor。纯字符查表，不用正则。

const (
	SYCClassBlock   = "block"
	SYCClassWarn    = "warn"
	SYCClassAllow   = "allow"
	SYCClassUnknown = "unknown"
)

var SYCBlock = []string{
	"!!",
	"javax.script",
	"scriptengine",
	"com.sun",
	"org.codehaus",
	"runtime",
	"java.lang.process",
}

var SYCWarn = []string{
	"!str",
	"!seq",
	"!map",
}

var SYCAllow = []string{
	"safe-constructor",
}

func SYCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SYCIn(list []string, v string) bool {
	for _, x := range list { if SYCLower(x) == v { return true } }
	return false
}

// SYCClassify 分类单个令牌。
func SYCClassify(tok string) string {
	v := SYCLower(tok)
	switch {
	case SYCIn(SYCBlock, v): return SYCClassBlock
	case SYCIn(SYCWarn, v): return SYCClassWarn
	case SYCIn(SYCAllow, v): return SYCClassAllow
	default: return SYCClassUnknown
	}
}
