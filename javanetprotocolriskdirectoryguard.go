package main

// javanetprotocolriskdirectoryguard.go —— Java 网络协议风险目录。
//
// 威胁模型：
//   JVM 默认支持 gopher/jar/netdoc/ftp 等协议，结合 URL 处理可触发 SSRF/反序列化，
//   出向应限定 https。纯字符查表，不用正则。

const (
	JNLClassBlock   = "block"
	JNLClassWarn    = "warn"
	JNLClassAllow   = "allow"
	JNLClassUnknown = "unknown"
)

var JNLBlock = []string{
	"gopher",
	"jar",
	"netdoc",
	"ftp",
	"file",
	"dict",
}

var JNLWarn = []string{
	"http",
	"mailto",
}

var JNLAllow = []string{
	"https",
}

func JNLLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JNLIn(list []string, v string) bool {
	for _, x := range list { if JNLLower(x) == v { return true } }
	return false
}

// JNLClassify 分类单个令牌。
func JNLClassify(tok string) string {
	v := JNLLower(tok)
	switch {
	case JNLIn(JNLBlock, v): return JNLClassBlock
	case JNLIn(JNLWarn, v): return JNLClassWarn
	case JNLIn(JNLAllow, v): return JNLClassAllow
	default: return JNLClassUnknown
	}
}
