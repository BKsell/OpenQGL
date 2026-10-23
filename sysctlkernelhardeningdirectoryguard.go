package main

// sysctlkernelhardeningdirectoryguard.go —— 内核硬化 sysctl 取值目录。
//
// 威胁模型：
//   kptr_restrict=0/dmesg_restrict=0/perf_event_paranoid 放开/ip_forward 等削弱内核信息保护或扩大网络面，
//   应按基线收紧。纯字符查表，不用正则。

const (
	SYSClassBlock   = "block"
	SYSClassWarn    = "warn"
	SYSClassAllow   = "allow"
	SYSClassUnknown = "unknown"
)

var SYSBlock = []string{
	"kptr_restrict=0",
	"dmesg_restrict=0",
	"perf_event_paranoid=-1",
	"ip_forward=1",
}

var SYSWarn = []string{
	"tcp_timestamps=1",
	"accept_source_route=1",
}

var SYSAllow = []string{
	"kptr_restrict=2",
	"dmesg_restrict=1",
}

func SYSLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SYSIn(list []string, v string) bool {
	for _, x := range list { if SYSLower(x) == v { return true } }
	return false
}

// SYSClassify 分类单个令牌。
func SYSClassify(tok string) string {
	v := SYSLower(tok)
	switch {
	case SYSIn(SYSBlock, v): return SYSClassBlock
	case SYSIn(SYSWarn, v): return SYSClassWarn
	case SYSIn(SYSAllow, v): return SYSClassAllow
	default: return SYSClassUnknown
	}
}
