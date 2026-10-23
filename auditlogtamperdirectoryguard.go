package main

// auditlogtamperdirectoryguard.go —— 审计日志防篡改目录。
//
// 威胁模型：
//   日志放 /tmp、可变可删的普通文件、无完整性链会被攻击者擦除痕迹，
//   应 append-only + 哈希链。纯字符查表，不用正则。

const (
	AUDClassBlock   = "block"
	AUDClassWarn    = "warn"
	AUDClassAllow   = "allow"
	AUDClassUnknown = "unknown"
)

var AUDBlock = []string{
	"log-in-tmp",
	"mutable-log",
	"no-integrity",
	"world-log",
}

var AUDWarn = []string{
	"json-append",
}

var AUDAllow = []string{
	"append-only",
	"hash-chain",
}

func AUDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func AUDIn(list []string, v string) bool {
	for _, x := range list { if AUDLower(x) == v { return true } }
	return false
}

// AUDClassify 分类单个令牌。
func AUDClassify(tok string) string {
	v := AUDLower(tok)
	switch {
	case AUDIn(AUDBlock, v): return AUDClassBlock
	case AUDIn(AUDWarn, v): return AUDClassWarn
	case AUDIn(AUDAllow, v): return AUDClassAllow
	default: return AUDClassUnknown
	}
}
