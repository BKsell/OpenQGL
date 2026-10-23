package main

// powershellexecbypassdirectoryguard.go —— PowerShell 危险参数/命令目录。
//
// 威胁模型：
//   -EncodedCommand、ExecutionPolicy Bypass、-nop、IEX/DownloadString 是无文件落地执行的典型手法，
//   白名单进程启动时应拒绝。纯字符查表，不用正则。

const (
	PSBClassBlock   = "block"
	PSBClassWarn    = "warn"
	PSBClassAllow   = "allow"
	PSBClassUnknown = "unknown"
)

var PSBBlock = []string{
	"-enc",
	"-encodedcommand",
	"bypass",
	"-exec",
	"-nop",
	"iex",
	"invoke-expression",
	"downloadstring",
	"invoke-webrequest",
}

var PSBWarn = []string{
	"-w",
	"hidden",
	"-noninteractive",
}

var PSBAllow = []string{
	"-file",
	"-command-allowlisted",
}

func PSBLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func PSBIn(list []string, v string) bool {
	for _, x := range list { if PSBLower(x) == v { return true } }
	return false
}

// PSBClassify 分类单个令牌。
func PSBClassify(tok string) string {
	v := PSBLower(tok)
	switch {
	case PSBIn(PSBBlock, v): return PSBClassBlock
	case PSBIn(PSBWarn, v): return PSBClassWarn
	case PSBIn(PSBAllow, v): return PSBClassAllow
	default: return PSBClassUnknown
	}
}
