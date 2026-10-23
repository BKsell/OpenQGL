package main

// jwtsecretentropydirectoryguard.go —— JWT 对称密钥强度目录。
//
// 威胁模型：
//   HS256 使用短密钥/默认值/changeme 可被离线爆破，
//   应至少 32 字节随机或改用非对称算法。纯字符查表，不用正则。

const (
	JSEClassBlock   = "block"
	JSEClassWarn    = "warn"
	JSEClassAllow   = "allow"
	JSEClassUnknown = "unknown"
)

var JSEBlock = []string{
	"none",
	"default-secret",
	"changeme",
	"short-secret",
	"secret",
}

var JSEWarn = []string{
	"low-entropy",
}

var JSEAllow = []string{
	"rs256",
	"32-byte-random",
}

func JSELower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JSEIn(list []string, v string) bool {
	for _, x := range list { if JSELower(x) == v { return true } }
	return false
}

// JSEClassify 分类单个令牌。
func JSEClassify(tok string) string {
	v := JSELower(tok)
	switch {
	case JSEIn(JSEBlock, v): return JSEClassBlock
	case JSEIn(JSEWarn, v): return JSEClassWarn
	case JSEIn(JSEAllow, v): return JSEClassAllow
	default: return JSEClassUnknown
	}
}
