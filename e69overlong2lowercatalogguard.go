package main

// e69overlong2lowercatalogguard.go —— 过長两字节 UTF-8 小写百分号目录。
//
// 威胁模型：
//   %c0%af 形式的过長 UTF-8 用两个字节表示 ASCII，旧解析器接受后还原 / 等危险字符而现代过滤器拒绝，解析差异可被利用，
//   危险过長序列应阻断。纯字符查表，不用正则。

const (
	E69O2LClassBlock   = "block"
	E69O2LClassWarn    = "warn"
	E69O2LClassAllow   = "allow"
	E69O2LClassUnknown = "unknown"
)

var E69O2LBlock = []string{
	"%c0%80",
	"%c0%81",
	"%c0%82",
	"%c0%83",
	"%c0%84",
	"%c0%85",
	"%c0%86",
	"%c0%87",
	"%c0%88",
	"%c0%8a",
	"%c0%8b",
	"%c0%8c",
	"%c0%8d",
	"%c0%8e",
	"%c0%8f",
	"%c0%90",
	"%c0%91",
	"%c0%92",
	"%c0%93",
	"%c0%94",
	"%c0%95",
	"%c0%96",
	"%c0%97",
	"%c0%98",
	"%c0%99",
	"%c0%9a",
	"%c0%9b",
	"%c0%9c",
	"%c0%9d",
	"%c0%9e",
	"%c0%9f",
	"%c0%a2",
	"%c0%a7",
	"%c0%a8",
	"%c0%a9",
	"%c0%ae",
	"%c0%af",
	"%c0%bc",
	"%c0%bd",
	"%c0%be",
	"%c0%bf",
	"%c1%80",
	"%c1%9b",
	"%c1%9c",
	"%c1%9d",
	"%c1%a0",
	"%c1%bb",
	"%c1%bc",
	"%c1%bd",
	"%c1%bf",
}

var E69O2LWarn = []string{
	"%c0%89",
	"%c0%a0",
	"%c0%a1",
	"%c0%a3",
	"%c0%a4",
	"%c0%a5",
	"%c0%a6",
	"%c0%aa",
	"%c0%ab",
	"%c0%ac",
	"%c0%ad",
	"%c0%b0",
	"%c0%b1",
	"%c0%b2",
	"%c0%b3",
	"%c0%b4",
	"%c0%b5",
	"%c0%b6",
	"%c0%b7",
	"%c0%b8",
	"%c0%b9",
	"%c0%ba",
	"%c0%bb",
	"%c1%81",
	"%c1%82",
	"%c1%83",
	"%c1%84",
	"%c1%85",
	"%c1%86",
	"%c1%87",
	"%c1%88",
	"%c1%89",
	"%c1%8a",
	"%c1%8b",
	"%c1%8c",
	"%c1%8d",
	"%c1%8e",
	"%c1%8f",
	"%c1%90",
	"%c1%91",
	"%c1%92",
	"%c1%93",
	"%c1%94",
	"%c1%95",
	"%c1%96",
	"%c1%97",
	"%c1%98",
	"%c1%99",
	"%c1%9a",
	"%c1%9e",
	"%c1%9f",
	"%c1%a1",
	"%c1%a2",
	"%c1%a3",
	"%c1%a4",
	"%c1%a5",
	"%c1%a6",
	"%c1%a7",
	"%c1%a8",
	"%c1%a9",
	"%c1%aa",
	"%c1%ab",
	"%c1%ac",
	"%c1%ad",
	"%c1%ae",
	"%c1%af",
	"%c1%b0",
	"%c1%b1",
	"%c1%b2",
	"%c1%b3",
	"%c1%b4",
	"%c1%b5",
	"%c1%b6",
	"%c1%b7",
	"%c1%b8",
	"%c1%b9",
	"%c1%ba",
	"%c1%be",
}

var E69O2LAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E69O2LLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E69O2LIn(list []string, v string) bool {
	for _, x := range list { if E69O2LLower(x) == v { return true } }
	return false
}

// E69O2LClassify 分类单个令牌。
func E69O2LClassify(tok string) string {
	v := E69O2LLower(tok)
	switch {
	case E69O2LIn(E69O2LBlock, v): return E69O2LClassBlock
	case E69O2LIn(E69O2LWarn, v): return E69O2LClassWarn
	case E69O2LIn(E69O2LAllow, v): return E69O2LClassAllow
	default: return E69O2LClassUnknown
	}
}
