package main

// reservedwinfilenamedirectoryguard.go —— Windows 保留设备文件名目录。
//
// 威胁模型：
//   CON/AUX/PRN/NUL/COM1-9/LPT1-9 是设备名，用作普通文件会写入设备或兼容性异常，
//   尾部点/空格也会被规范化丢弃。纯字符查表，不用正则。

const (
	RWFClassBlock   = "block"
	RWFClassWarn    = "warn"
	RWFClassAllow   = "allow"
	RWFClassUnknown = "unknown"
)

var RWFBlock = []string{
	"con",
	"aux",
	"prn",
	"nul",
	"com1",
	"com9",
	"lpt1",
	"lpt9",
	"clock$",
}

var RWFWarn = []string{
	"trailing-dot",
	"trailing-space",
}

var RWFAllow = []string{
	"normal-file",
}

func RWFLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func RWFIn(list []string, v string) bool {
	for _, x := range list { if RWFLower(x) == v { return true } }
	return false
}

// RWFClassify 分类单个令牌。
func RWFClassify(tok string) string {
	v := RWFLower(tok)
	switch {
	case RWFIn(RWFBlock, v): return RWFClassBlock
	case RWFIn(RWFWarn, v): return RWFClassWarn
	case RWFIn(RWFAllow, v): return RWFClassAllow
	default: return RWFClassUnknown
	}
}
