package main

// webdavmethodcatalogguard.go —— WebDAV/危险 HTTP 方法目录。
//
// 威胁模型：
//   PROPFIND/MOVE/COPY/PUT/DELETE/LOCK 等 WebDAV 方法可列目录、改写或移动资源，出向与本地管理面默认禁用，
//   只读安全方法放行。纯字符查表，不用正则。

const (
	WDMClassBlock   = "block"
	WDMClassWarn    = "warn"
	WDMClassAllow   = "allow"
	WDMClassUnknown = "unknown"
)

var WDMBlock = []string{
	"PROPPATCH",
	"MKCOL",
	"COPY",
	"MOVE",
	"LOCK",
	"UNLOCK",
	"MKCALENDAR",
	"VERSION-CONTROL",
	"CHECKIN",
	"CHECKOUT",
	"UNCHECKOUT",
	"MERGE",
	"MKACTIVITY",
	"BASELINE-CONTROL",
	"MKWORKSPACE",
	"ACL",
	"BIND",
	"UNBIND",
}

var WDMWarn = []string{
	"PROPFIND",
	"SEARCH",
	"REPORT",
	"NOTIFY",
	"POLL",
	"SUBSCRIBE",
	"UNSUBSCRIBE",
}

var WDMAllow = []string{
	"GET",
	"HEAD",
	"OPTIONS",
}

func WDMLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func WDMIn(list []string, v string) bool {
	for _, x := range list { if WDMLower(x) == v { return true } }
	return false
}

// WDMClassify 分类单个令牌。
func WDMClassify(tok string) string {
	v := WDMLower(tok)
	switch {
	case WDMIn(WDMBlock, v): return WDMClassBlock
	case WDMIn(WDMWarn, v): return WDMClassWarn
	case WDMIn(WDMAllow, v): return WDMClassAllow
	default: return WDMClassUnknown
	}
}
