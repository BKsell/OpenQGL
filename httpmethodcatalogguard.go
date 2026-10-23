package main

// httpmethodcatalogguard.go —— HTTP 方法风险目录。
//
// 威胁模型：
//   TRACE 触发 XST，PUT/DELETE/PATCH/LOCK/UNLOCK 在未鉴权服务上可改资源，CONNECT 建立隧道。纯字符查表，不用正则。

const (
	HMDClassBlock   = "block"
	HMDClassWarn    = "warn"
	HMDClassAllow   = "allow"
	HMDClassUnknown = "unknown"
)

var HMDBlock = []string{
	"TRACE",
	"TRACK",
	"PUT",
	"DELETE",
	"CONNECT",
}

var HMDWarn = []string{
	"POST",
	"PATCH",
	"LOCK",
	"UNLOCK",
	"PROPFIND",
	"PROPPATCH",
	"MKCOL",
	"COPY",
	"MOVE",
	"PURGE",
	"LINK",
	"UNLINK",
}

var HMDAllow = []string{
	"GET",
	"HEAD",
	"OPTIONS",
}

func HMDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func HMDIn(list []string, v string) bool {
	for _, x := range list { if HMDLower(x) == v { return true } }
	return false
}

// HMDClassify 分类单个令牌。
func HMDClassify(tok string) string {
	v := HMDLower(tok)
	switch {
	case HMDIn(HMDBlock, v): return HMDClassBlock
	case HMDIn(HMDWarn, v): return HMDClassWarn
	case HMDIn(HMDAllow, v): return HMDClassAllow
	default: return HMDClassUnknown
	}
}
