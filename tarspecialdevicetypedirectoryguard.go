package main

// tarspecialdevicetypedirectoryguard.go —— tar 特殊设备成员类型目录。
//
// 威胁模型：
//   tar 成员类型为块/字符设备、FIFO 或 mknod 设备号可落地恶意设备节点，
//   解包只允许常规文件与目录。纯字符查表，不用正则。

const (
	TSDClassBlock   = "block"
	TSDClassWarn    = "warn"
	TSDClassAllow   = "allow"
	TSDClassUnknown = "unknown"
)

var TSDBlock = []string{
	"block-device",
	"char-device",
	"fifo",
	"mknod",
	"major-minor",
}

var TSDWarn = []string{
	"sparse",
	"hardlink",
}

var TSDAllow = []string{
	"regular-file",
	"directory",
	"symlink-checked",
}

func TSDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func TSDIn(list []string, v string) bool {
	for _, x := range list { if TSDLower(x) == v { return true } }
	return false
}

// TSDClassify 分类单个令牌。
func TSDClassify(tok string) string {
	v := TSDLower(tok)
	switch {
	case TSDIn(TSDBlock, v): return TSDClassBlock
	case TSDIn(TSDWarn, v): return TSDClassWarn
	case TSDIn(TSDAllow, v): return TSDClassAllow
	default: return TSDClassUnknown
	}
}
