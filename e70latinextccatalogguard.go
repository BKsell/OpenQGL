package main

// e70latinextccatalogguard.go —— 拉丁扩展 C 码位目录。
//
// 威胁模型：
//   拉丁扩展 C 中部分字母与 ASCII 近似，可用于同形混淆，
//   应 NFKC 归一化后判定。纯字符查表，不用正则。

const (
	E70T52ClassBlock   = "block"
	E70T52ClassWarn    = "warn"
	E70T52ClassAllow   = "allow"
	E70T52ClassUnknown = "unknown"
)

var E70T52Block = []string{
}

var E70T52Warn = []string{
	"U+2C60",
	"U+2C61",
	"U+2C62",
	"U+2C63",
	"U+2C64",
	"U+2C65",
	"U+2C66",
	"U+2C67",
	"U+2C68",
	"U+2C69",
	"U+2C6A",
	"U+2C6B",
	"U+2C6C",
	"U+2C6D",
	"U+2C6E",
	"U+2C6F",
	"U+2C70",
	"U+2C71",
	"U+2C72",
	"U+2C73",
	"U+2C74",
	"U+2C75",
	"U+2C76",
	"U+2C77",
	"U+2C78",
	"U+2C79",
	"U+2C7A",
	"U+2C7B",
	"U+2C7C",
	"U+2C7D",
	"U+2C7E",
	"U+2C7F",
}

var E70T52Allow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70T52Lower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70T52In(list []string, v string) bool {
	for _, x := range list { if E70T52Lower(x) == v { return true } }
	return false
}

// E70T52Classify 分类单个令牌。
func E70T52Classify(tok string) string {
	v := E70T52Lower(tok)
	switch {
	case E70T52In(E70T52Block, v): return E70T52ClassBlock
	case E70T52In(E70T52Warn, v): return E70T52ClassWarn
	case E70T52In(E70T52Allow, v): return E70T52ClassAllow
	default: return E70T52ClassUnknown
	}
}
