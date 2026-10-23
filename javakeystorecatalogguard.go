package main

// javakeystorecatalogguard.go —— 密钥库类型与加载方式目录。
//
// 威胁模型：
//   信任库/密钥库类型、可空密码、系统默认 cacerts 被替换都会改变信任根。本模块维护密钥库类型与加载策略
//   目录，纯字符，不用正则。

const (
	JKCClassBlock   = "block"
	JKCClassWarn    = "warn"
	JKCClassAllow   = "allow"
	JKCClassUnknown = "unknown"
)

var JKCBlock = []string{
	"PKCS12-EMPTY-PASSWORD",
	"JKS-DEFAULT-CACERTS",
	"PEM-DIR-AS-KEYSTORE",
	"WINDOWS-MY-FORCE",
	"KEYCHAIN-FORCE-TRUST",
}

var JKCWarn = []string{
	"JCEKS",
	"JKS",
	"PKCS11",
	"DKS",
	"BKS",
}

var JKCAllow = []string{
	"PKCS12",
	"PKCS12-STRICT",
}

func JKCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JKCIn(list []string, v string) bool {
	for _, x := range list { if JKCLower(x) == v { return true } }
	return false
}

// JKCClassify 分类单个令牌。
func JKCClassify(tok string) string {
	v := JKCLower(tok)
	switch {
	case JKCIn(JKCBlock, v): return JKCClassBlock
	case JKCIn(JKCWarn, v): return JKCClassWarn
	case JKCIn(JKCAllow, v): return JKCClassAllow
	default: return JKCClassUnknown
	}
}
