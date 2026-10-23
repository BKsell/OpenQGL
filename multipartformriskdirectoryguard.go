package main

// multipartformriskdirectoryguard.go —— multipart 表单风险字段目录。
//
// 威胁模型：
//   boundary 中注入 CRLF、filename 携带路径或提供 Content-Transfer-Encoding 可绕过解析，
//   服务端应只取文件名部分。纯字符查表，不用正则。

const (
	MPBClassBlock   = "block"
	MPBClassWarn    = "warn"
	MPBClassAllow   = "allow"
	MPBClassUnknown = "unknown"
)

var MPBBlock = []string{
	"filename=..\\",
	"filename=/",
	"content-transfer-encoding",
	"boundary=",
}

var MPBWarn = []string{
	"filename=",
	"name=",
}

var MPBAllow = []string{
	"content-type",
	"multipart/form-data",
}

func MPBLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func MPBIn(list []string, v string) bool {
	for _, x := range list { if MPBLower(x) == v { return true } }
	return false
}

// MPBClassify 分类单个令牌。
func MPBClassify(tok string) string {
	v := MPBLower(tok)
	switch {
	case MPBIn(MPBBlock, v): return MPBClassBlock
	case MPBIn(MPBWarn, v): return MPBClassWarn
	case MPBIn(MPBAllow, v): return MPBClassAllow
	default: return MPBClassUnknown
	}
}
