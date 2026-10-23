package main

// unsafelockfilelocationdirectoryguard.go —— 锁文件不安全位置目录。
//
// 威胁模型：
//   锁文件放可写 /etc、世界可写目录或为符号链接时可被替换造成 TOCTOU，
//   应放 /run/lock 并 O_NOFOLLOW。纯字符查表，不用正则。

const (
	LFLClassBlock   = "block"
	LFLClassWarn    = "warn"
	LFLClassAllow   = "allow"
	LFLClassUnknown = "unknown"
)

var LFLBlock = []string{
	"/etc-write",
	"world-lock",
	"symlink-lock",
	"/tmp-lock",
}

var LFLWarn = []string{
	"nfs-lock",
}

var LFLAllow = []string{
	"/run/lock",
}

func LFLLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func LFLIn(list []string, v string) bool {
	for _, x := range list { if LFLLower(x) == v { return true } }
	return false
}

// LFLClassify 分类单个令牌。
func LFLClassify(tok string) string {
	v := LFLLower(tok)
	switch {
	case LFLIn(LFLBlock, v): return LFLClassBlock
	case LFLIn(LFLWarn, v): return LFLClassWarn
	case LFLIn(LFLAllow, v): return LFLClassAllow
	default: return LFLClassUnknown
	}
}
