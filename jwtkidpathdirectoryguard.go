package main

// jwtkidpathdirectoryguard.go —— JWT kid 危险取值目录。
//
// 威胁模型：
//   kid 出现 ../、/dev/null 或 SQL 片段可路径穿越/注入到密钥查找，
//   kid 只能作为 JWK 集合中的受控标识。纯字符查表，不用正则。

const (
	JKPClassBlock   = "block"
	JKPClassWarn    = "warn"
	JKPClassAllow   = "allow"
	JKPClassUnknown = "unknown"
)

var JKPBlock = []string{
	"../",
	"/dev/null",
	"../../",
	"' or ",
	";--",
	"null",
}

var JKPWarn = []string{
	"static-kid",
}

var JKPAllow = []string{
	"jwks-kid",
}

func JKPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JKPIn(list []string, v string) bool {
	for _, x := range list { if JKPLower(x) == v { return true } }
	return false
}

// JKPClassify 分类单个令牌。
func JKPClassify(tok string) string {
	v := JKPLower(tok)
	switch {
	case JKPIn(JKPBlock, v): return JKPClassBlock
	case JKPIn(JKPWarn, v): return JKPClassWarn
	case JKPIn(JKPAllow, v): return JKPClassAllow
	default: return JKPClassUnknown
	}
}
