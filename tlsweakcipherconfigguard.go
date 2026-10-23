package main

// tlsweakcipherconfigguard.go —— TLS 弱密码套件配置目录。
//
// 威胁模型：
//   RC4/3DES/DES/EXPORT/NULL/匿名 DH/MD5 套件已可被解密或无认证，
//   应只留 AEAD 与前向保密套件。纯字符查表，不用正则。

const (
	TWCClassBlock   = "block"
	TWCClassWarn    = "warn"
	TWCClassAllow   = "allow"
	TWCClassUnknown = "unknown"
)

var TWCBlock = []string{
	"rc4",
	"3des",
	"des",
	"export",
	"null",
	"anon",
	"md5",
	"_ecdh_",
}

var TWCWarn = []string{
	"cbc",
	"tls_rsa_",
}

var TWCAllow = []string{
	"aes-gcm",
	"chacha20-poly1305",
	"ecdhe",
}

func TWCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TWCIn(list []string, v string) bool {
	for _, x := range list { if TWCLower(x) == v { return true } }
	return false
}

// TWCClassify 分类单个令牌。
func TWCClassify(tok string) string {
	v := TWCLower(tok)
	switch {
	case TWCIn(TWCBlock, v): return TWCClassBlock
	case TWCIn(TWCWarn, v): return TWCClassWarn
	case TWCIn(TWCAllow, v): return TWCClassAllow
	default: return TWCClassUnknown
	}
}
