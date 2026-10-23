package main

// ipencodingnotationdirectoryguard.go —— IP 非常规编码记法目录。
//
// 威胁模型：
//   十进制整数、十六进制 0x、八进制 0、IPv4-mapped 与 zone% 形式可绕过字符串黑名单，
//   应统一标准化后再判定。纯字符查表，不用正则。

const (
	IENClassBlock   = "block"
	IENClassWarn    = "warn"
	IENClassAllow   = "allow"
	IENClassUnknown = "unknown"
)

var IENBlock = []string{
	"0x",
	"0177",
	"::ffff:",
	"%25",
	"decimal-int-ip",
}

var IENWarn = []string{
	"mixed-radix",
	"hex-ip",
}

var IENAllow = []string{
	"dotted-quad",
	"canonical-ipv6",
}

func IENLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func IENIn(list []string, v string) bool {
	for _, x := range list { if IENLower(x) == v { return true } }
	return false
}

// IENClassify 分类单个令牌。
func IENClassify(tok string) string {
	v := IENLower(tok)
	switch {
	case IENIn(IENBlock, v): return IENClassBlock
	case IENIn(IENWarn, v): return IENClassWarn
	case IENIn(IENAllow, v): return IENClassAllow
	default: return IENClassUnknown
	}
}
