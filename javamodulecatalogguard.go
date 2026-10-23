package main

// javamodulecatalogguard.go —— JPMS 内部模块/包风险目录。
//
// 威胁模型：
//   --add-opens/--add-exports 的目标若是 jdk.internal/sun 内部包，等价于打开全部后门。本模块维护内部包
//   与应用包目录，纯字符，不用正则。

const (
	JMCClassBlock   = "block"
	JMCClassWarn    = "warn"
	JMCClassAllow   = "allow"
	JMCClassUnknown = "unknown"
)

var JMCBlock = []string{
	"jdk.internal.misc",
	"sun.misc",
	"sun.reflect",
	"jdk.internal.reflect",
	"jdk.internal.loader",
	"sun.security",
	"jdk.internal.org.objectweb",
	"sun.instrument",
	"jdk.internal.vm.annotation",
	"sun.nio.ch",
	"sun.net.www.protocol",
}

var JMCWarn = []string{
	"java.lang.reflect",
	"java.lang.invoke",
	"java.security",
	"javax.crypto",
	"java.net.http",
	"jdk.net",
	"com.sun.net.httpserver",
}

var JMCAllow = []string{
	"java.base",
	"java.logging",
	"java.net.http",
	"java.sql",
	"java.desktop",
	"java.management",
}

func JMCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JMCIn(list []string, v string) bool {
	for _, x := range list { if JMCLower(x) == v { return true } }
	return false
}

// JMCClassify 分类单个令牌。
func JMCClassify(tok string) string {
	v := JMCLower(tok)
	switch {
	case JMCIn(JMCBlock, v): return JMCClassBlock
	case JMCIn(JMCWarn, v): return JMCClassWarn
	case JMCIn(JMCAllow, v): return JMCClassAllow
	default: return JMCClassUnknown
	}
}
