package main

// dhgroupweakdirectoryguard.go —— Diffie-Hellman 弱群目录。
//
// 威胁模型：
//   1024 位及以下 MODP/FFDHE 群可被国家级破解，
//   应至少 2048，优先 ECDHE/Curve25519。纯字符查表，不用正则。

const (
	DHWClassBlock   = "block"
	DHWClassWarn    = "warn"
	DHWClassAllow   = "allow"
	DHWClassUnknown = "unknown"
)

var DHWBlock = []string{
	"modp512",
	"modp768",
	"modp1024",
	"ffdhe1024",
	"group1",
}

var DHWWarn = []string{
	"ffdhe2048",
	"modp2048",
}

var DHWAllow = []string{
	"ffdhe4096",
	"curve25519",
	"x25519",
}

func DHWLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func DHWIn(list []string, v string) bool {
	for _, x := range list { if DHWLower(x) == v { return true } }
	return false
}

// DHWClassify 分类单个令牌。
func DHWClassify(tok string) string {
	v := DHWLower(tok)
	switch {
	case DHWIn(DHWBlock, v): return DHWClassBlock
	case DHWIn(DHWWarn, v): return DHWClassWarn
	case DHWIn(DHWAllow, v): return DHWClassAllow
	default: return DHWClassUnknown
	}
}
