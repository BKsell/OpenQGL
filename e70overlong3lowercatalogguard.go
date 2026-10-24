package main

// e70overlong3lowercatalogguard.go —— 过長三字节 UTF-8 小写目录。
//
// 威胁模型：
//   %e0%80%80 形式用三字节表示 ASCII（如 %e0%80%af 还原 /），仅拒绝两字节过長形式会被三字节绕过，
//   危险过長序列应阻断。纯字符查表，不用正则。

const (
	E70O3LClassBlock   = "block"
	E70O3LClassWarn    = "warn"
	E70O3LClassAllow   = "allow"
	E70O3LClassUnknown = "unknown"
)

var E70O3LBlock = []string{
	"%e0%80%80",
	"%e0%80%81",
	"%e0%80%82",
	"%e0%80%83",
	"%e0%80%84",
	"%e0%80%85",
	"%e0%80%86",
	"%e0%80%87",
	"%e0%80%88",
	"%e0%80%8a",
	"%e0%80%8b",
	"%e0%80%8c",
	"%e0%80%8d",
	"%e0%80%8e",
	"%e0%80%8f",
	"%e0%80%90",
	"%e0%80%91",
	"%e0%80%92",
	"%e0%80%93",
	"%e0%80%94",
	"%e0%80%95",
	"%e0%80%96",
	"%e0%80%97",
	"%e0%80%98",
	"%e0%80%99",
	"%e0%80%9a",
	"%e0%80%9b",
	"%e0%80%9c",
	"%e0%80%9d",
	"%e0%80%9e",
	"%e0%80%9f",
	"%e0%80%a2",
	"%e0%80%a7",
	"%e0%80%a8",
	"%e0%80%a9",
	"%e0%80%ae",
	"%e0%80%af",
	"%e0%80%bc",
	"%e0%80%bd",
	"%e0%80%be",
	"%e0%80%bf",
	"%e0%80%c0",
	"%e0%80%db",
	"%e0%80%dc",
	"%e0%80%dd",
	"%e0%80%e0",
	"%e0%80%fb",
	"%e0%80%fc",
	"%e0%80%fd",
	"%e0%80%ff",
}

var E70O3LWarn = []string{
	"%e0%80%89",
	"%e0%80%a0",
	"%e0%80%a1",
	"%e0%80%a3",
	"%e0%80%a4",
	"%e0%80%a5",
	"%e0%80%a6",
	"%e0%80%aa",
	"%e0%80%ab",
	"%e0%80%ac",
	"%e0%80%ad",
	"%e0%80%b0",
	"%e0%80%b1",
	"%e0%80%b2",
	"%e0%80%b3",
	"%e0%80%b4",
	"%e0%80%b5",
	"%e0%80%b6",
	"%e0%80%b7",
	"%e0%80%b8",
	"%e0%80%b9",
	"%e0%80%ba",
	"%e0%80%bb",
	"%e0%80%c1",
	"%e0%80%c2",
	"%e0%80%c3",
	"%e0%80%c4",
	"%e0%80%c5",
	"%e0%80%c6",
	"%e0%80%c7",
	"%e0%80%c8",
	"%e0%80%c9",
	"%e0%80%ca",
	"%e0%80%cb",
	"%e0%80%cc",
	"%e0%80%cd",
	"%e0%80%ce",
	"%e0%80%cf",
	"%e0%80%d0",
	"%e0%80%d1",
	"%e0%80%d2",
	"%e0%80%d3",
	"%e0%80%d4",
	"%e0%80%d5",
	"%e0%80%d6",
	"%e0%80%d7",
	"%e0%80%d8",
	"%e0%80%d9",
	"%e0%80%da",
	"%e0%80%de",
	"%e0%80%df",
	"%e0%80%e1",
	"%e0%80%e2",
	"%e0%80%e3",
	"%e0%80%e4",
	"%e0%80%e5",
	"%e0%80%e6",
	"%e0%80%e7",
	"%e0%80%e8",
	"%e0%80%e9",
	"%e0%80%ea",
	"%e0%80%eb",
	"%e0%80%ec",
	"%e0%80%ed",
	"%e0%80%ee",
	"%e0%80%ef",
	"%e0%80%f0",
	"%e0%80%f1",
	"%e0%80%f2",
	"%e0%80%f3",
	"%e0%80%f4",
	"%e0%80%f5",
	"%e0%80%f6",
	"%e0%80%f7",
	"%e0%80%f8",
	"%e0%80%f9",
	"%e0%80%fa",
	"%e0%80%fe",
}

var E70O3LAllow = []string{
	"ascii-only",
	"nfkc-normalized",
	"punycode-label",
}

func E70O3LLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func E70O3LIn(list []string, v string) bool {
	for _, x := range list { if E70O3LLower(x) == v { return true } }
	return false
}

// E70O3LClassify 分类单个令牌。
func E70O3LClassify(tok string) string {
	v := E70O3LLower(tok)
	switch {
	case E70O3LIn(E70O3LBlock, v): return E70O3LClassBlock
	case E70O3LIn(E70O3LWarn, v): return E70O3LClassWarn
	case E70O3LIn(E70O3LAllow, v): return E70O3LClassAllow
	default: return E70O3LClassUnknown
	}
}
