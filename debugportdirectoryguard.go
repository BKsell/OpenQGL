package main

// debugportdirectoryguard.go —— 调试/诊断开关目录。
//
// 威胁模型：
//   --inspect/JDWP/Xdebug/5005/9229 调试口暴露即允许远程代码或内存读写，
//   生产环境必须关闭。纯字符查表，不用正则。

const (
	DBPClassBlock   = "block"
	DBPClassWarn    = "warn"
	DBPClassAllow   = "allow"
	DBPClassUnknown = "unknown"
)

var DBPBlock = []string{
	"--inspect",
	"--inspect-brk",
	"jdwp",
	"xdebug",
	"agentlib:jdwp",
	"5005",
	"9229",
}

var DBPWarn = []string{
	"-agentpath",
	"debug",
	"dt_socket",
}

var DBPAllow = []string{
	"release",
	"disabled",
}

func DBPLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func DBPIn(list []string, v string) bool {
	for _, x := range list { if DBPLower(x) == v { return true } }
	return false
}

// DBPClassify 分类单个令牌。
func DBPClassify(tok string) string {
	v := DBPLower(tok)
	switch {
	case DBPIn(DBPBlock, v): return DBPClassBlock
	case DBPIn(DBPWarn, v): return DBPClassWarn
	case DBPIn(DBPAllow, v): return DBPClassAllow
	default: return DBPClassUnknown
	}
}
