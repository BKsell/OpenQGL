package main

// jwtclaimriskcatalogguard.go —— JWT 高风险 header/claim 目录。
//
// 威胁模型：
//   jku/x5u 使接收方按 URL 拉取密钥可被指向攻击者 JWK，kid/x5c 路径与注入需复核，标准注册声明放行。纯字符查表，不用正则。

const (
	JWCClassBlock   = "block"
	JWCClassWarn    = "warn"
	JWCClassAllow   = "allow"
	JWCClassUnknown = "unknown"
)

var JWCBlock = []string{
	"jku",
	"x5u",
}

var JWCWarn = []string{
	"kid",
	"x5c",
	"x5t",
	"x5t#S256",
	"typ",
	"cty",
	"cnf",
	"jti",
	"sip_from",
	"azp",
}

var JWCAllow = []string{
	"iss",
	"sub",
	"aud",
	"exp",
	"nbf",
	"iat",
	"nonce",
	"at_hash",
	"c_hash",
	"auth_time",
	"acr",
	"amr",
	"scope",
}

func JWCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JWCIn(list []string, v string) bool {
	for _, x := range list { if JWCLower(x) == v { return true } }
	return false
}

// JWCClassify 分类单个令牌。
func JWCClassify(tok string) string {
	v := JWCLower(tok)
	switch {
	case JWCIn(JWCBlock, v): return JWCClassBlock
	case JWCIn(JWCWarn, v): return JWCClassWarn
	case JWCIn(JWCAllow, v): return JWCClassAllow
	default: return JWCClassUnknown
	}
}
