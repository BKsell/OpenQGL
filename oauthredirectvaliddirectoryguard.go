package main

// oauthredirectvaliddirectoryguard.go —— OAuth redirect_uri 危险取值目录。
//
// 威胁模型：
//   redirect_uri 指向 localhost/file:/http://、通配或路径穿越可劫持授权码，
//   必须与注册的精确 https 回调完全相等。纯字符查表，不用正则。

const (
	ORVClassBlock   = "block"
	ORVClassWarn    = "warn"
	ORVClassAllow   = "allow"
	ORVClassUnknown = "unknown"
)

var ORVBlock = []string{
	"localhost",
	"127.0.0.1",
	"file:",
	"http://",
	"*",
	"/../",
	"0.0.0.0",
}

var ORVWarn = []string{
	"path-suffix",
	"subdomain",
}

var ORVAllow = []string{
	"exact-https-registered",
}

func ORVLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func ORVIn(list []string, v string) bool {
	for _, x := range list { if ORVLower(x) == v { return true } }
	return false
}

// ORVClassify 分类单个令牌。
func ORVClassify(tok string) string {
	v := ORVLower(tok)
	switch {
	case ORVIn(ORVBlock, v): return ORVClassBlock
	case ORVIn(ORVWarn, v): return ORVClassWarn
	case ORVIn(ORVAllow, v): return ORVClassAllow
	default: return ORVClassUnknown
	}
}
