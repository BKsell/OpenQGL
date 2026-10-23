package main

// corepatternpipedirectoryguard.go —— core_pattern 管道风险目录。
//
// 威胁模型：
//   kernel.core_pattern 以 | 开头会在内核崩溃时以 root 执行 helper，
//   容器/主机应禁止写该 sysctl。纯字符查表，不用正则。

const (
	CPPClassBlock   = "block"
	CPPClassWarn    = "warn"
	CPPClassAllow   = "allow"
	CPPClassUnknown = "unknown"
)

var CPPBlock = []string{
	"|/",
	"core_pattern-pipe",
	"suid_dumpable=1",
}

var CPPWarn = []string{
	"core-to-path",
}

var CPPAllow = []string{
	"core=0",
}

func CPPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CPPIn(list []string, v string) bool {
	for _, x := range list { if CPPLower(x) == v { return true } }
	return false
}

// CPPClassify 分类单个令牌。
func CPPClassify(tok string) string {
	v := CPPLower(tok)
	switch {
	case CPPIn(CPPBlock, v): return CPPClassBlock
	case CPPIn(CPPWarn, v): return CPPClassWarn
	case CPPIn(CPPAllow, v): return CPPClassAllow
	default: return CPPClassUnknown
	}
}
