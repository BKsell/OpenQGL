package main

// refreshtokenrotationdirectoryguard.go —— Refresh Token 轮换目录。
//
// 威胁模型：
//   refresh token 长期不轮换、重用不检测会使被盗令牌无限续期，
//   应一次性轮换并检测重用。纯字符查表，不用正则。

const (
	ORRClassBlock   = "block"
	ORRClassWarn    = "warn"
	ORRClassAllow   = "allow"
	ORRClassUnknown = "unknown"
)

var ORRBlock = []string{
	"no-rotation",
	"reuse-allowed",
	"long-ttl-infinite",
}

var ORRWarn = []string{
	"long-ttl",
}

var ORRAllow = []string{
	"rotate-on-use",
	"reuse-detection",
}

func ORRLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func ORRIn(list []string, v string) bool {
	for _, x := range list { if ORRLower(x) == v { return true } }
	return false
}

// ORRClassify 分类单个令牌。
func ORRClassify(tok string) string {
	v := ORRLower(tok)
	switch {
	case ORRIn(ORRBlock, v): return ORRClassBlock
	case ORRIn(ORRWarn, v): return ORRClassWarn
	case ORRIn(ORRAllow, v): return ORRClassAllow
	default: return ORRClassUnknown
	}
}
