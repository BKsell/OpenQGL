package main

// hostheaderinjectiondirectoryguard.go —— Host 头注入相关头目录。
//
// 威胁模型：
//   Host 及各类转发 Host 覆盖头来自请求即可污染密码重置链接、缓存键与虚拟主机路由，
//   只能信任受控代理写入的单一头，客户端提供的覆盖值应阻断。纯字符查表，不用正则。

const (
	HHIClassBlock   = "block"
	HHIClassWarn    = "warn"
	HHIClassAllow   = "allow"
	HHIClassUnknown = "unknown"
)

var HHIBlock = []string{
	"x-http-host-override",
	"x-forwarded-server",
	"x-original-host",
	"x-host",
	"x-forwarded-host",
	"host",
}

var HHIWarn = []string{
	"forwarded",
	"x-forwarded-proto",
	"referer",
	"origin",
}

var HHIAllow = []string{
	"accept",
	"date",
	"user-agent",
}

func HHILower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func HHIIn(list []string, v string) bool {
	for _, x := range list { if HHILower(x) == v { return true } }
	return false
}

// HHIClassify 分类单个令牌。
func HHIClassify(tok string) string {
	v := HHILower(tok)
	switch {
	case HHIIn(HHIBlock, v): return HHIClassBlock
	case HHIIn(HHIWarn, v): return HHIClassWarn
	case HHIIn(HHIAllow, v): return HHIClassAllow
	default: return HHIClassUnknown
	}
}
