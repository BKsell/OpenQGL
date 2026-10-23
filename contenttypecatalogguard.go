package main

// contenttypecatalogguard.go —— Content-Type 可执行/歧义目录。
//
// 威胁模型：
//   响应 Content-Type 决定下载还是渲染。text/html 配图片扩展名、application/x-msdownload、
//   active content 类型需强制下载并隔离。本模块维护类型目录，纯字符，不用正则。

const (
	CTCClassBlock   = "block"
	CTCClassWarn    = "warn"
	CTCClassAllow   = "allow"
	CTCClassUnknown = "unknown"
)

var CTCBlock = []string{
	"text/html",
	"application/xhtml+xml",
	"application/x-msdownload",
	"application/x-shockwave-flash",
	"application/java-archive",
	"application/x-java-jnlp-file",
	"application/hta",
	"text/javascript",
	"application/javascript",
	"multipart/x-mixed-replace",
}

var CTCWarn = []string{
	"application/octet-stream",
	"text/xml",
	"application/xml",
	"image/svg+xml",
	"application/pdf",
	"application/x-dosexec",
}

var CTCAllow = []string{
	"image/png",
	"image/jpeg",
	"image/gif",
	"image/webp",
	"text/plain",
	"application/json",
	"audio/mpeg",
	"video/mp4",
	"font/woff2",
}

func CTCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CTCIn(list []string, v string) bool {
	for _, x := range list { if CTCLower(x) == v { return true } }
	return false
}

// CTCClassify 分类单个令牌。
func CTCClassify(tok string) string {
	v := CTCLower(tok)
	switch {
	case CTCIn(CTCBlock, v): return CTCClassBlock
	case CTCIn(CTCWarn, v): return CTCClassWarn
	case CTCIn(CTCAllow, v): return CTCClassAllow
	default: return CTCClassUnknown
	}
}
