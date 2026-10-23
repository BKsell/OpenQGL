package main

// slsaprovenancelleveldirectoryguard.go —— SLSA 证明等级目录。
//
// 威胁模型：
//   无 provenance 或 SLSA v0、builder 不可信不能证明构件来源，
//   应要求 v1+ 且验证构建器身份。纯字符查表，不用正则。

const (
	SLSAClassBlock   = "block"
	SLSAClassWarn    = "warn"
	SLSAClassAllow   = "allow"
	SLSAClassUnknown = "unknown"
)

var SLSABlock = []string{
	"v0",
	"provenance-absent",
	"builder-untrusted",
}

var SLSAWarn = []string{
	"v1",
	"slsa-v0.1",
}

var SLSAAllow = []string{
	"v1-verified",
	"v1.1",
}

func SLSALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SLSAIn(list []string, v string) bool {
	for _, x := range list { if SLSALower(x) == v { return true } }
	return false
}

// SLSAClassify 分类单个令牌。
func SLSAClassify(tok string) string {
	v := SLSALower(tok)
	switch {
	case SLSAIn(SLSABlock, v): return SLSAClassBlock
	case SLSAIn(SLSAWarn, v): return SLSAClassWarn
	case SLSAIn(SLSAAllow, v): return SLSAClassAllow
	default: return SLSAClassUnknown
	}
}
