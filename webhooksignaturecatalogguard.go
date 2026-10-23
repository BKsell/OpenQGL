package main

// webhooksignaturecatalogguard.go —— Webhook 签名方案风险目录。
//
// 威胁模型：
//   明文/无签名、md5/sha1、共享密钥放 URL、不校验时间戳的 HMAC 可被重放伪造。纯字符查表，不用正则。

const (
	WHSClassBlock   = "block"
	WHSClassWarn    = "warn"
	WHSClassAllow   = "allow"
	WHSClassUnknown = "unknown"
)

var WHSBlock = []string{
	"none",
	"plaintext",
	"md5",
	"sha1",
	"HMAC-MD5",
	"HMAC-SHA1",
	"X-Hub-Signature",
}

var WHSWarn = []string{
	"v0",
	"sha256",
	"sha1=",
	"sha256=",
	"X-Hub-Signature-256",
	"X-Slack-Signature",
	"X-Square-Signature",
	"X-WC-Webhook-Signature",
	"X-Signature",
}

var WHSAllow = []string{
	"HMAC-SHA256",
	"HMAC-SHA384",
	"HMAC-SHA512",
	"Ed25519",
	"v1",
	"Stripe-Signature",
	"svix-id",
	"svix-timestamp",
	"svix-signature",
	"t",
}

func WHSLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func WHSIn(list []string, v string) bool {
	for _, x := range list { if WHSLower(x) == v { return true } }
	return false
}

// WHSClassify 分类单个令牌。
func WHSClassify(tok string) string {
	v := WHSLower(tok)
	switch {
	case WHSIn(WHSBlock, v): return WHSClassBlock
	case WHSIn(WHSWarn, v): return WHSClassWarn
	case WHSIn(WHSAllow, v): return WHSClassAllow
	default: return WHSClassUnknown
	}
}
