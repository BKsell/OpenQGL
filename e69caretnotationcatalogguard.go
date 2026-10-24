package main

// e69caretnotationcatalogguard.go —— 终端插入符控制字符目录。
//
// 威胁模型：
//   ^@ ^[ ^? 等插入符记号在终端/串口协议中表示 NUL/ESC/DEL，写入终端可触发控制序列，
//   控制字符记号应阻断。纯字符查表，不用正则。

const (
	E69CARClassBlock   = "block"
	E69CARClassWarn    = "warn"
	E69CARClassAllow   = "allow"
	E69CARClassUnknown = "unknown"
)

var E69CARBlock = []string{
	"^@",
	"^A",
	"^B",
	"^C",
	"^D",
	"^E",
	"^F",
	"^G",
	"^H",
	"^J",
	"^K",
	"^L",
	"^M",
	"^N",
	"^O",
	"^P",
	"^Q",
	"^R",
	"^S",
	"^T",
	"^U",
	"^V",
	"^W",
	"^X",
	"^Y",
	"^Z",
	"^[",
	"^\\",
	"^]",
	"^^",
	"^_",
	"^?",
}

var E69CARWarn = []string{
	"^I",
}

var E69CARAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69CARLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69CARIn(list []string, v string) bool {
	for _, x := range list { if E69CARLower(x) == v { return true } }
	return false
}

// E69CARClassify 分类单个令牌。
func E69CARClassify(tok string) string {
	v := E69CARLower(tok)
	switch {
	case E69CARIn(E69CARBlock, v): return E69CARClassBlock
	case E69CARIn(E69CARWarn, v): return E69CARClassWarn
	case E69CARIn(E69CARAllow, v): return E69CARClassAllow
	default: return E69CARClassUnknown
	}
}
