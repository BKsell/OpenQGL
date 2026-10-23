package main

// pkcs11mechanismcatalogguard.go —— PKCS#11 弱机制目录。
//
// 威胁模型：
//   PKCS#11/HSM 中 CKM_RSA_PKCS（无 OAEP/PSS）、CKM_DES/RC4/ECB、MD5/HMAC 类机制过弱需禁用。纯字符查表，不用正则。

const (
	P11ClassBlock   = "block"
	P11ClassWarn    = "warn"
	P11ClassAllow   = "allow"
	P11ClassUnknown = "unknown"
)

var P11Block = []string{
	"CKM_DES_ECB",
	"CKM_DES_CBC",
	"CKM_DES_CBC_PAD",
	"CKM_DES3_ECB",
	"CKM_CAST_ECB",
	"CKM_CAST3_ECB",
	"CKM_CAST5_ECB",
	"CKM_CDMF_ECB",
	"CKM_CDMF_CBC",
	"CKM_RC2_ECB",
	"CKM_RC2_CBC",
	"CKM_RC2_CBC_PAD",
	"CKM_RC4",
	"CKM_RSA_PKCS",
	"CKM_RSA_X_509",
	"CKM_RSA_9796",
	"CKM_MD5",
	"CKM_MD5_HMAC",
	"CKM_SHA_1_HMAC",
	"CKM_SSL3_PRE_MASTER_KEY_GEN",
	"CKM_SSL3_MASTER_KEY_DERIVE",
}

var P11Warn = []string{
	"CKM_DES3_CBC",
	"CKM_DES3_CBC_PAD",
	"CKM_SHA1_RSA_PKCS",
	"CKM_SHA1_RSA_X9_31",
	"CKM_SHA_1",
	"CKM_ECDSA_SHA1",
	"CKM_DSA_SHA1",
	"CKM_ECDH1_DERIVE",
	"CKM_RSA_PKCS_KEY_PAIR_GEN",
}

var P11Allow = []string{
	"CKM_RSA_PKCS_OAEP",
	"CKM_RSA_PKCS_PSS",
	"CKM_SHA256_RSA_PKCS",
	"CKM_SHA384_RSA_PKCS",
	"CKM_SHA512_RSA_PKCS",
	"CKM_SHA256_RSA_PKCS_PSS",
	"CKM_AES_KEY_GEN",
	"CKM_AES_GCM",
	"CKM_AES_CBC",
	"CKM_ECDSA",
	"CKM_ECDSA_SHA256",
	"CKM_ECDH1_COFACTOR_DERIVE",
	"CKM_AES_KEY_WRAP",
}

func P11Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func P11In(list []string, v string) bool {
	for _, x := range list { if P11Lower(x) == v { return true } }
	return false
}

// P11Classify 分类单个令牌。
func P11Classify(tok string) string {
	v := P11Lower(tok)
	switch {
	case P11In(P11Block, v): return P11ClassBlock
	case P11In(P11Warn, v): return P11ClassWarn
	case P11In(P11Allow, v): return P11ClassAllow
	default: return P11ClassUnknown
	}
}
