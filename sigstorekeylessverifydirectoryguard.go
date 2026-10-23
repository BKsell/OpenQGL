package main

// sigstorekeylessverifydirectoryguard.go —— Sigstore 验签风险目录。
//
// 威胁模型：
//   关闭 Fulcio/Rekor、不校验透明日志或验签时忽略 bundle 等于不验证来源，
//   应 cosign verify 校验证书与 Rekor 条目。纯字符查表，不用正则。

const (
	SSTClassBlock   = "block"
	SSTClassWarn    = "warn"
	SSTClassAllow   = "allow"
	SSTClassUnknown = "unknown"
)

var SSTBlock = []string{
	"keyless-none",
	"fulcio-off",
	"rekor-off",
	"ignore-bundle",
}

var SSTWarn = []string{
	"rekor-optional",
}

var SSTAllow = []string{
	"cosign-verify-bundle",
}

func SSTLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SSTIn(list []string, v string) bool {
	for _, x := range list { if SSTLower(x) == v { return true } }
	return false
}

// SSTClassify 分类单个令牌。
func SSTClassify(tok string) string {
	v := SSTLower(tok)
	switch {
	case SSTIn(SSTBlock, v): return SSTClassBlock
	case SSTIn(SSTWarn, v): return SSTClassWarn
	case SSTIn(SSTAllow, v): return SSTClassAllow
	default: return SSTClassUnknown
	}
}
