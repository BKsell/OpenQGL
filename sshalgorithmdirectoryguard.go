package main

// sshalgorithmdirectoryguard.go —— SSH 弱算法目录。
//
// 威胁模型：
//   ssh-rsa SHA-1、ssh-dss、group1/group14-sha1、arcfour、hmac-md5 已弱，
//   应使用 Ed25519/Curve25519/AES-GCM。纯字符查表，不用正则。

const (
	AHSClassBlock   = "block"
	AHSClassWarn    = "warn"
	AHSClassAllow   = "allow"
	AHSClassUnknown = "unknown"
)

var AHSBlock = []string{
	"ssh-rsa",
	"ssh-dss",
	"diffie-hellman-group1",
	"arcfour",
	"hmac-md5",
	"none",
}

var AHSWarn = []string{
	"group14-sha1",
	"aes-cbc",
	"hmac-sha1",
}

var AHSAllow = []string{
	"ed25519",
	"curve25519-sha256",
	"aes256-gcm",
}

func AHSLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func AHSIn(list []string, v string) bool {
	for _, x := range list { if AHSLower(x) == v { return true } }
	return false
}

// AHSClassify 分类单个令牌。
func AHSClassify(tok string) string {
	v := AHSLower(tok)
	switch {
	case AHSIn(AHSBlock, v): return AHSClassBlock
	case AHSIn(AHSWarn, v): return AHSClassWarn
	case AHSIn(AHSAllow, v): return AHSClassAllow
	default: return AHSClassUnknown
	}
}
