package main

// pypidependencyhashdirectoryguard.go —— Python 包哈希锁定目录。
//
// 威胁模型：
//   --trusted-host 走 http、requirements 无哈希或浮动版本可被投毒，
//   应 --require-hashes 固定 sha256。纯字符查表，不用正则。

const (
	PYDClassBlock   = "block"
	PYDClassWarn    = "warn"
	PYDClassAllow   = "allow"
	PYDClassUnknown = "unknown"
)

var PYDBlock = []string{
	"--trusted-host",
	"http://",
	"no-hash",
	"*",
}

var PYDWarn = []string{
	"unpinned",
}

var PYDAllow = []string{
	"sha256-pinned",
	"require-hashes",
}

func PYDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func PYDIn(list []string, v string) bool {
	for _, x := range list { if PYDLower(x) == v { return true } }
	return false
}

// PYDClassify 分类单个令牌。
func PYDClassify(tok string) string {
	v := PYDLower(tok)
	switch {
	case PYDIn(PYDBlock, v): return PYDClassBlock
	case PYDIn(PYDWarn, v): return PYDClassWarn
	case PYDIn(PYDAllow, v): return PYDClassAllow
	default: return PYDClassUnknown
	}
}
