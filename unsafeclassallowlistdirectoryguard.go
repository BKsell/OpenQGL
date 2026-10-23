package main

// unsafeclassallowlistdirectoryguard.go —— 反序列化 gadget 类/包目录。
//
// 威胁模型：
//   commons-collections/Groovy/BCEL/Rome/c3p0/Spring AOP 等是知名反序列化 gadget 链来源，
//   ObjectInputStream 应启用类白名单。纯字符查表，不用正则。

const (
	UCAClassBlock   = "block"
	UCAClassWarn    = "warn"
	UCAClassAllow   = "allow"
	UCAClassUnknown = "unknown"
)

var UCABlock = []string{
	"commons-collections",
	"groovy",
	"bcel",
	"rome",
	"c3p0",
	"spring-aop",
	"jython",
	"beanutils",
}

var UCAWarn = []string{
	"jdk.proxy",
	"annotations",
}

var UCAAllow = []string{
	"java.lang",
	"arraylist",
	"primitives",
}

func UCALower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func UCAIn(list []string, v string) bool {
	for _, x := range list { if UCALower(x) == v { return true } }
	return false
}

// UCAClassify 分类单个令牌。
func UCAClassify(tok string) string {
	v := UCALower(tok)
	switch {
	case UCAIn(UCABlock, v): return UCAClassBlock
	case UCAIn(UCAWarn, v): return UCAClassWarn
	case UCAIn(UCAAllow, v): return UCAClassAllow
	default: return UCAClassUnknown
	}
}
