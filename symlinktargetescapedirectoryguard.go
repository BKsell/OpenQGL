package main

// symlinktargetescapedirectoryguard.go —— 符号链接逃逸目标目录。
//
// 威胁模型：
//   链接目标指向绝对路径、../../、\\?\ 或 NFS 等可在跟随链接时写出根目录，
//   解包/打开应在根内规范化后校验。纯字符查表，不用正则。

const (
	SYLClassBlock   = "block"
	SYLClassWarn    = "warn"
	SYLClassAllow   = "allow"
	SYLClassUnknown = "unknown"
)

var SYLBlock = []string{
	"->/etc",
	"->/",
	"../../",
	"\\\\?\\",
	"nfs:",
	"/proc",
	"/sys",
}

var SYLWarn = []string{
	"relative-parent",
	"->..",
}

var SYLAllow = []string{
	"within-root",
}

func SYLLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SYLIn(list []string, v string) bool {
	for _, x := range list { if SYLLower(x) == v { return true } }
	return false
}

// SYLClassify 分类单个令牌。
func SYLClassify(tok string) string {
	v := SYLLower(tok)
	switch {
	case SYLIn(SYLBlock, v): return SYLClassBlock
	case SYLIn(SYLWarn, v): return SYLClassWarn
	case SYLIn(SYLAllow, v): return SYLClassAllow
	default: return SYLClassUnknown
	}
}
