package main

// zipbombmetricdirectoryguard.go —— 压缩炸弹指标目录。
//
// 威胁模型：
//   超高压缩比、嵌套 zip、重复零填充小解压巨文件可耗尽磁盘/内存，
//   解包应按解压后总量与比率设限。纯字符查表，不用正则。

const (
	ZBMClassBlock   = "block"
	ZBMClassWarn    = "warn"
	ZBMClassAllow   = "allow"
	ZBMClassUnknown = "unknown"
)

var ZBMBlock = []string{
	"ratio-1000",
	"nested-zip",
	"zip-bomb",
	"repeated-zeros",
}

var ZBMWarn = []string{
	"size-mismatch",
	"many-small-entries",
}

var ZBMAllow = []string{
	"stored-method",
	"ratio-bounded",
}

func ZBMLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func ZBMIn(list []string, v string) bool {
	for _, x := range list { if ZBMLower(x) == v { return true } }
	return false
}

// ZBMClassify 分类单个令牌。
func ZBMClassify(tok string) string {
	v := ZBMLower(tok)
	switch {
	case ZBMIn(ZBMBlock, v): return ZBMClassBlock
	case ZBMIn(ZBMWarn, v): return ZBMClassWarn
	case ZBMIn(ZBMAllow, v): return ZBMClassAllow
	default: return ZBMClassUnknown
	}
}
