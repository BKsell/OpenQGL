package main

// hashalgcatalogguard.go —— 哈希/签名算法强度目录。
//
// 威胁模型：
//   外部 API 指定的算法（Mojang SHA1、authlib SHA256、Modrinth sha1/sha512）按各自要求保留；本地完整性与
//   签名新用途不得选被攻破的 MD5/SHA1。本模块仅给算法分级，纯查表，不用正则。

const (
	HACClassBlock   = "block"
	HACClassWarn    = "warn"
	HACClassAllow   = "allow"
	HACClassUnknown = "unknown"
)

var HACBlock = []string{
	"md2",
	"md4",
	"md5",
	"sha0",
	"sha-0",
	"sha1",
	"sha-1",
	"ripemd",
	"ripemd160",
	"md5withrsa",
	"sha1withrsa",
	"hmac-md5",
	"hmacsha1",
	"dsawithsha1",
	"ecdsa-with-sha1",
}

var HACWarn = []string{
	"sha224",
	"sha-224",
	"sha384",
	"sha-384",
	"sha512-224",
	"sha512-256",
	"sha3-224",
}

var HACAllow = []string{
	"sha-256",
	"sha256",
	"sha-512",
	"sha512",
	"sha3-256",
	"sha3-512",
	"hmac-sha256",
	"hmacsha256",
	"hmac-sha512",
	"sha256withrsa",
	"sha512withrsa",
	"ed25519",
	"ed448",
}

func HACLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func HACIn(list []string, v string) bool {
	for _, x := range list { if HACLower(x) == v { return true } }
	return false
}

// HACClassify 分类单个令牌。
func HACClassify(tok string) string {
	v := HACLower(tok)
	switch {
	case HACIn(HACBlock, v): return HACClassBlock
	case HACIn(HACWarn, v): return HACClassWarn
	case HACIn(HACAllow, v): return HACClassAllow
	default: return HACClassUnknown
	}
}
