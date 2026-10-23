package main

// insecureumaskdirectoryguard.go —— 不安全 umask 取值目录。
//
// 威胁模型：
//   umask=0 使新建文件默认全局可写，022 对机密文件仍偏宽，
//   敏感目录应 077/027。纯字符查表，不用正则。

const (
	UMKClassBlock   = "block"
	UMKClassWarn    = "warn"
	UMKClassAllow   = "allow"
	UMKClassUnknown = "unknown"
)

var UMKBlock = []string{
	"000",
	"0",
}

var UMKWarn = []string{
	"022",
}

var UMKAllow = []string{
	"077",
	"027",
}

func UMKLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func UMKIn(list []string, v string) bool {
	for _, x := range list { if UMKLower(x) == v { return true } }
	return false
}

// UMKClassify 分类单个令牌。
func UMKClassify(tok string) string {
	v := UMKLower(tok)
	switch {
	case UMKIn(UMKBlock, v): return UMKClassBlock
	case UMKIn(UMKWarn, v): return UMKClassWarn
	case UMKIn(UMKAllow, v): return UMKClassAllow
	default: return UMKClassUnknown
	}
}
