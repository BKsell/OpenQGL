package main

// signaturealgorithmcatalogguard.go —— 签名算法强度目录。
//
// 威胁模型：
//   none/MD2/MD5/SHA1 及对应 RSA/ECDSA/HMAC 签名算法已可碰撞或被选入降级，应阻断，PSS/Ed25519/SHA256+ 放行。纯字符查表，不用正则。

const (
	SIAClassBlock   = "block"
	SIAClassWarn    = "warn"
	SIAClassAllow   = "allow"
	SIAClassUnknown = "unknown"
)

var SIABlock = []string{
	"none",
	"MD2",
	"MD5",
	"SHA1",
	"RSA-MD5",
	"RSA-SHA1",
	"HMAC-MD5",
	"HMAC-SHA1",
	"ecdsa-sha1",
}

var SIAWarn = []string{
	"RSASSA-PKCS1-v1_5",
	"SHA1withRSA",
	"SHA1withECDSA",
	"DSA-SHA1",
	"MD5withRSA",
}

var SIAAllow = []string{
	"RSASSA-PSS",
	"RSA-SHA256",
	"RSA-SHA384",
	"RSA-SHA512",
	"ECDSA",
	"ECDSA-SHA256",
	"ECDSA-SHA384",
	"Ed25519",
	"EdDSA",
	"SHA256",
	"SHA384",
	"SHA512",
	"HMAC-SHA256",
}

func SIALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SIAIn(list []string, v string) bool {
	for _, x := range list { if SIALower(x) == v { return true } }
	return false
}

// SIAClassify 分类单个令牌。
func SIAClassify(tok string) string {
	v := SIALower(tok)
	switch {
	case SIAIn(SIABlock, v): return SIAClassBlock
	case SIAIn(SIAWarn, v): return SIAClassWarn
	case SIAIn(SIAAllow, v): return SIAClassAllow
	default: return SIAClassUnknown
	}
}
