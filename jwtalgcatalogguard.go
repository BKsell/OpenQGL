package main

// jwtalgcatalogguard.go —— JWT 签名算法目录。
//
// 威胁模型：
//   JWT alg=none/空算法可伪造身份，HS/RS 混淆与弱 HMAC 需复核，强非对称算法放行。纯字符查表，不用正则。

const (
	JALClassBlock   = "block"
	JALClassWarn    = "warn"
	JALClassAllow   = "allow"
	JALClassUnknown = "unknown"
)

var JALBlock = []string{
	"none",
	"None",
	"NONE",
	"nOnE",
	"no",
	"null",
	"empty",
	"HS128",
	"hs128",
}

var JALWarn = []string{
	"HS256",
	"HS384",
	"HS512",
	"hs256",
	"hs384",
	"hs512",
	"HMAC",
	"hmac",
	"ES256K",
}

var JALAllow = []string{
	"RS256",
	"RS384",
	"RS512",
	"rs256",
	"rs384",
	"rs512",
	"ES256",
	"ES384",
	"ES512",
	"es256",
	"es384",
	"es512",
	"PS256",
	"PS384",
	"PS512",
	"ps256",
	"ps384",
	"ps512",
	"EdDSA",
	"eddsa",
	"Ed25519",
	"Ed448",
}

func JALLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JALIn(list []string, v string) bool {
	for _, x := range list { if JALLower(x) == v { return true } }
	return false
}

// JALClassify 分类单个令牌。
func JALClassify(tok string) string {
	v := JALLower(tok)
	switch {
	case JALIn(JALBlock, v): return JALClassBlock
	case JALIn(JALWarn, v): return JALClassWarn
	case JALIn(JALAllow, v): return JALClassAllow
	default: return JALClassUnknown
	}
}
