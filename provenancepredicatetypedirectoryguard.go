package main

// provenancepredicatetypedirectoryguard.go —— 出处证明谓词类型目录。
//
// 威胁模型：
//   仅接受泛化/未知谓词无法确认是 SLSA 构建出处，
//   应校验 https://slsa.dev/provenance 谓词。纯字符查表，不用正则。

const (
	PRVClassBlock   = "block"
	PRVClassWarn    = "warn"
	PRVClassAllow   = "allow"
	PRVClassUnknown = "unknown"
)

var PRVBlock = []string{
	"generic-predicate",
	"unknown-predicate",
	"in-toto-generic",
}

var PRVWarn = []string{
	"slsa-v0.1",
	"slsa/v0.2",
}

var PRVAllow = []string{
	"slsa/v1",
	"slsa/v1.0",
}

func PRVLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func PRVIn(list []string, v string) bool {
	for _, x := range list { if PRVLower(x) == v { return true } }
	return false
}

// PRVClassify 分类单个令牌。
func PRVClassify(tok string) string {
	v := PRVLower(tok)
	switch {
	case PRVIn(PRVBlock, v): return PRVClassBlock
	case PRVIn(PRVWarn, v): return PRVClassWarn
	case PRVIn(PRVAllow, v): return PRVClassAllow
	default: return PRVClassUnknown
	}
}
