package main

// certificatepinningdisabledirectoryguard.go —— 证书钉扎关闭配置目录。
//
// 威胁模型：
//   禁用钉扎、信任用户添加 CA、cleartext 配置会削弱移动客户端防中间人能力，
//   应保留内置 pins。纯字符查表，不用正则。

const (
	CPDClassBlock   = "block"
	CPDClassWarn    = "warn"
	CPDClassAllow   = "allow"
	CPDClassUnknown = "unknown"
)

var CPDBlock = []string{
	"pinning-disabled",
	"trustkit-swizzle",
	"cleartext-traffic",
	"user-ca-trusted",
}

var CPDWarn = []string{
	"pin-expired",
}

var CPDAllow = []string{
	"built-in-pins",
}

func CPDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CPDIn(list []string, v string) bool {
	for _, x := range list { if CPDLower(x) == v { return true } }
	return false
}

// CPDClassify 分类单个令牌。
func CPDClassify(tok string) string {
	v := CPDLower(tok)
	switch {
	case CPDIn(CPDBlock, v): return CPDClassBlock
	case CPDIn(CPDWarn, v): return CPDClassWarn
	case CPDIn(CPDAllow, v): return CPDClassAllow
	default: return CPDClassUnknown
	}
}
