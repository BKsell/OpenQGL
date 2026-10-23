package main

// commandshellseparatorcatalogguard.go —— 命令分隔/替换符目录。
//
// 威胁模型：
//   拼接外部命令行时，分号/管道/与/反引号/$()/换行等分隔替换符允许命令链执行。本目录收录分隔符及其编码，
//   纯字符精确匹配，不执行命令，不用正则。

const (
	CSMClassBlock   = "block"
	CSMClassWarn    = "warn"
	CSMClassAllow   = "allow"
	CSMClassUnknown = "unknown"
)

var CSMBlock = []string{
	";",
	";;",
	";|",
	"|",
	"||",
	"&",
	"&&",
	"&|",
	"$()",
	"`",
	"`id`",
	"$(",
	")",
	"%0a",
	"%0d",
	"%0d%0a",
	"%0A",
	"%0D",
	"\\n",
	"\\r",
	"\\r\\n",
	"\\nr",
	">",
	">>",
	"<",
	"<<",
	">&",
	"<&",
	"|+",
	"|&",
	"%00",
	"%26",
	"%7c",
	"%3b",
	"%60",
	"%24%28",
	"newline",
	"\\ncmd",
	";rm",
	";cmd",
	"|cmd",
	"&&cmd",
	"||cmd",
	"$(cmd)",
	"`cmd`",
	";cat",
	";wget",
	";curl",
	";nc",
	";bash",
	";sh",
	";cmd.exe",
	";powershell",
	"|bash",
	"|sh",
}

var CSMWarn = []string{
	"-d",
	"-f",
	"-e",
	"-x",
	"-v",
	"-n",
	"-q",
	"--",
	"-c",
	"-s",
	"-a",
	"-o",
	"-z",
	"-t",
	"-l",
	"-h",
	"-p",
	"-r",
	"-w",
	"%09",
	"%20",
	"\\",
	"/",
	":",
	"=",
	"+",
	"@",
	"#",
	"!",
	"^",
	"%24",
	"%28",
	"%29",
}

var CSMAllow = []string{
	"--version",
	"--help",
	"--config",
	"--port",
	"--host",
	"--user",
	"--name",
	"--file",
	"--dir",
	"--log",
	"--json",
	"--quiet",
	"--verbose",
	"--timeout",
	"--output",
	"--input",
	"--type",
	"--mode",
}

func CSMLower(x string) string {
	return x
}

func CSMIn(list []string, v string) bool {
	for _, x := range list { if CSMLower(x) == v { return true } }
	return false
}

// CSMClassify 分类单个令牌。
func CSMClassify(tok string) string {
	v := CSMLower(tok)
	switch {
	case CSMIn(CSMBlock, v): return CSMClassBlock
	case CSMIn(CSMWarn, v): return CSMClassWarn
	case CSMIn(CSMAllow, v): return CSMClassAllow
	default: return CSMClassUnknown
	}
}
