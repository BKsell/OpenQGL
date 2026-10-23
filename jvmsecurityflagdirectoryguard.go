package main

// jvmsecurityflagdirectoryguard.go —— JVM 危险启动标志目录。
//
// 威胁模型：
//   关闭 SecurityManager、noverify、信任所有证书、开放 JMX 都会削弱沙箱或暴露管理面，
//   启动 MC/JVM 子进程应拒绝这些标志。纯字符查表，不用正则。

const (
	JSFClassBlock   = "block"
	JSFClassWarn    = "warn"
	JSFClassAllow   = "allow"
	JSFClassUnknown = "unknown"
)

var JSFBlock = []string{
	"djava.security.manager=allow",
	"noverify",
	"xverify:none",
	"trustall",
	"jmxremote",
	"disableattachmechanism=false",
}

var JSFWarn = []string{
	"dcom.sun.management",
	"djava.net.preferipv4",
}

var JSFAllow = []string{
	"xmx",
	"xss",
	"xx:+use",
}

func JSFLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JSFIn(list []string, v string) bool {
	for _, x := range list { if JSFLower(x) == v { return true } }
	return false
}

// JSFClassify 分类单个令牌。
func JSFClassify(tok string) string {
	v := JSFLower(tok)
	switch {
	case JSFIn(JSFBlock, v): return JSFClassBlock
	case JSFIn(JSFWarn, v): return JSFClassWarn
	case JSFIn(JSFAllow, v): return JSFClassAllow
	default: return JSFClassUnknown
	}
}
