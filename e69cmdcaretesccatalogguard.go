package main

// e69cmdcaretesccatalogguard.go —— cmd.exe 插入符转义字节目录。
//
// 威胁模型：
//   cmd.exe 用 ^ 转义 & < > | ( ) " 等元字符，插入符在解析阶段被剥离，纯字节黑名单可被 ^< 绕过，
//   危险元字符转义应阻断。纯字符查表，不用正则。

const (
	E69CMCClassBlock   = "block"
	E69CMCClassWarn    = "warn"
	E69CMCClassAllow   = "allow"
	E69CMCClassUnknown = "unknown"
)

var E69CMCBlock = []string{
	"^\"",
	"^(",
	"^)",
	"^<",
	"^>",
	"^|",
}

var E69CMCWarn = []string{
	"^&",
	"^^",
}

var E69CMCAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69CMCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69CMCIn(list []string, v string) bool {
	for _, x := range list { if E69CMCLower(x) == v { return true } }
	return false
}

// E69CMCClassify 分类单个令牌。
func E69CMCClassify(tok string) string {
	v := E69CMCLower(tok)
	switch {
	case E69CMCIn(E69CMCBlock, v): return E69CMCClassBlock
	case E69CMCIn(E69CMCWarn, v): return E69CMCClassWarn
	case E69CMCIn(E69CMCAllow, v): return E69CMCClassAllow
	default: return E69CMCClassUnknown
	}
}
