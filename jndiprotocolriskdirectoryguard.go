package main

// jndiprotocolriskdirectoryguard.go —— JNDI 危险协议目录。
//
// 威胁模型：
//   JNDI 解析 ldap/rmi/iiop/dns 等远程引用是 Log4Shell 类漏洞的利用通道，
//   lookup 输入必须白名单 java:comp/env。纯字符查表，不用正则。

const (
	JNPClassBlock   = "block"
	JNPClassWarn    = "warn"
	JNPClassAllow   = "allow"
	JNPClassUnknown = "unknown"
)

var JNPBlock = []string{
	"ldap",
	"ldaps",
	"rmi",
	"iiop",
	"dns",
	"corba",
}

var JNPWarn = []string{
	"ldaps+tls",
}

var JNPAllow = []string{
	"java:comp/env",
}

func JNPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JNPIn(list []string, v string) bool {
	for _, x := range list { if JNPLower(x) == v { return true } }
	return false
}

// JNPClassify 分类单个令牌。
func JNPClassify(tok string) string {
	v := JNPLower(tok)
	switch {
	case JNPIn(JNPBlock, v): return JNPClassBlock
	case JNPIn(JNPWarn, v): return JNPClassWarn
	case JNPIn(JNPAllow, v): return JNPClassAllow
	default: return JNPClassUnknown
	}
}
