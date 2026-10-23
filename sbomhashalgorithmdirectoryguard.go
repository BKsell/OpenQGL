package main

// sbomhashalgorithmdirectoryguard.go —— SBOM 组件标识算法目录。
//
// 威胁模型：
//   SBOM 用 md5/sha1 标识组件、缺 purl/cpe 会导致成分不可信或无法对漏洞，
//   应用 sha256 与标准包 URL。纯字符查表，不用正则。

const (
	SBAClassBlock   = "block"
	SBAClassWarn    = "warn"
	SBAClassAllow   = "allow"
	SBAClassUnknown = "unknown"
)

var SBABlock = []string{
	"md5",
	"sha1",
	"no-purl",
	"no-cpe",
}

var SBAWarn = []string{
	"component-name-only",
}

var SBAAllow = []string{
	"sha256",
	"purl",
	"cpe",
}

func SBALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SBAIn(list []string, v string) bool {
	for _, x := range list { if SBALower(x) == v { return true } }
	return false
}

// SBAClassify 分类单个令牌。
func SBAClassify(tok string) string {
	v := SBALower(tok)
	switch {
	case SBAIn(SBABlock, v): return SBAClassBlock
	case SBAIn(SBAWarn, v): return SBAClassWarn
	case SBAIn(SBAAllow, v): return SBAClassAllow
	default: return SBAClassUnknown
	}
}
