package main

// pidfileunsafelocationdirectoryguard.go —— PID 文件不安全位置目录。
//
// 威胁模型：
//   PID 文件放世界可写 /tmp 且名字可预测，可被符号链接抢占发送信号到别的进程，
//   应放 /run 并 0644 + O_NOFOLLOW。纯字符查表，不用正则。

const (
	PIDClassBlock   = "block"
	PIDClassWarn    = "warn"
	PIDClassAllow   = "allow"
	PIDClassUnknown = "unknown"
)

var PIDBlock = []string{
	"/tmp/app.pid",
	"world-pid",
	"predictable-pid",
}

var PIDWarn = []string{
	"pid-reuse",
}

var PIDAllow = []string{
	"/run-0644",
	"no-follow",
}

func PIDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func PIDIn(list []string, v string) bool {
	for _, x := range list { if PIDLower(x) == v { return true } }
	return false
}

// PIDClassify 分类单个令牌。
func PIDClassify(tok string) string {
	v := PIDLower(tok)
	switch {
	case PIDIn(PIDBlock, v): return PIDClassBlock
	case PIDIn(PIDWarn, v): return PIDClassWarn
	case PIDIn(PIDAllow, v): return PIDClassAllow
	default: return PIDClassUnknown
	}
}
