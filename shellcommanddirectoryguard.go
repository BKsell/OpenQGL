package main

// shellcommanddirectoryguard.go —— Shell/终端危险命令词目录。
//
// 威胁模型：
//   启动器拼接外部命令行时，下载执行、编码绕过、管道反弹、账号/卷影拷贝、防火墙关停等命令词属高危，
//   构建/压缩等常规命令词放行。纯字符查表（精确命令名/开关），不执行，不用正则。

// CVD 风险类别。
const (
	CVDClassBlock = "block"
	CVDClassWarn  = "warn"
	CVDClassAllow = "allow"
)

const (
	CVDReasonBlock   = "cvd-input-hits-blocked-catalog"
	CVDReasonWarn    = "cvd-input-hits-review-catalog"
	CVDReasonPrefix  = "cvd-input-hits-dangerous-prefix"
	CVDReasonEmpty   = "cvd-input-is-empty"
)

var CVDBlock = []string{
	"curl",
	"wget",
	"Invoke-WebRequest",
	"Invoke-RestMethod",
	"iwr",
	"irm",
	"certutil",
	"bitsadmin",
	"regsvr32",
	"mshta",
	"rundll32",
	"msiexec",
	"msbuild",
	"installutil",
	"cscript",
	"wscript",
	"powershell",
	"pwsh",
	"cmd",
	"nc",
	"ncat",
	"netcat",
	"nmap",
	"bash",
	"sh",
	"python",
	"perl",
	"ruby",
	"php",
	"ftp",
	"tftp",
	"ssh",
	"telnet",
	"rsh",
	"rexec",
	"at",
	"schtasks",
	"sc",
	"wmic",
	"vssadmin",
	"wbadmin",
	"bcdedit",
	"diskpart",
	"cipher",
	"net",
	"netsh",
	"net1",
	"icacls",
	"takeown",
	"cacls",
	"attrib",
	"esentutl",
	"expand",
	"makecab",
	"extrac32",
	"-enc",
	"-encodedcommand",
	"-e",
	"-ep",
	"-exec",
	"ExecutionPolicy",
	"-bypass",
	"-nop",
	"-noprofile",
	"-w",
	"-windowstyle",
	"hidden",
	"-noninteractive",
	"-Command",
	"-c",
	"-File",
	"-f",
	"-NoProfile",
	"-ExecutionPolicy",
	"-OutputFormat",
	"Text",
	"-EncodedCommand",
	"/e:jscript",
	"/e:vbscript",
	"/ru",
	"/create",
	"/run",
	"/delete",
	"/change",
	"/download",
	"/upload",
	"/transfer",
	"/decode",
	"-urldecode",
	"-urlcache",
	"/split",
	"-s",
	"/p",
	"/Q",
	"/quiet",
	"/qn",
	"/norestart",
	"-jar",
	"-cp",
	"-ExecutionPolicy.Bypass",
	"Add-MpPreference",
	"Set-MpPreference",
	"New-Service",
	"sc.exe",
	"Start-Process",
	"DownloadString",
	"DownloadFile",
	"DownloadData",
	"IEX",
	"Invoke-Expression",
	"iex",
	"FromBase64String",
	"Get-Content",
	"Set-Content",
	"-OutFile",
	"New-Object",
	"Net.WebClient",
	"Net.HttpClient",
	"Start-BitsTransfer",
	"mklink",
	"New-Item",
	"-itemtype",
	"SymbolicLink",
	"Junction",
	"Remove-Item",
	"rm",
	"del",
	"rmdir",
	"Stop-Service",
	"Stop-Process",
	"taskkill",
	"/f",
	"/im",
	"shutdown",
	"/r",
	"/s",
	"/t",
	"/a",
}

var CVDWarn = []string{
	"tar",
	"7z",
	"7za",
	"unzip",
	"zip",
	"gzip",
	"gunzip",
	"xcopy",
	"robocopy",
	"copy",
	"move",
	"ren",
	"rename",
	"mkdir",
	"type",
	"more",
	"find",
	"findstr",
	"sort",
	"clip",
	"echo",
	"set",
	"setx",
	"reg",
	"regedit",
	"query",
	"start",
	"call",
	"runas",
	"scheduled",
	"crontab",
	"launchctl",
	"systemctl",
	"service",
	"kill",
	"pkill",
	"killall",
	"ps",
	"top",
	"lsof",
	"netstat",
	"ss",
	"ip",
	"ifconfig",
	"route",
	"arp",
	"ping",
	"tracert",
	"traceroute",
	"nslookup",
	"dig",
	"host",
	"whoami",
	"id",
	"uname",
	"hostname",
	"systeminfo",
	"ver",
	"where",
	"which",
	"env",
	"printenv",
	"chmod",
	"chown",
	"chgrp",
	"ln",
	"mount",
	"umount",
	"fsutil",
	"subst",
	"user",
	"localgroup",
	"share",
	"use",
	"view",
}

var CVDAllow = []string{
	"go",
	"gofmt",
	"goimports",
	"node",
	"npm",
	"npx",
	"git",
	"gitk",
	"svn",
	"cargo",
	"rustc",
	"javac",
	"java",
	"javaw",
	"dotnet",
	"gcc",
	"g++",
	"clang",
	"cl",
	"make",
	"cmake",
	"ninja",
	"gradle",
	"mvn",
	"python3",
	"pip",
	"pip3",
	"venv",
	"virtualenv",
	"uv",
	"conda",
	"docker.build",
	"code",
	"devenv",
	"notepad",
	"calc",
	"explorer",
}

var CVDPrefixLit = []string{
}
var CVDPrefixReason = []string{
}

// CVDFinding 表示一条命中。
type CVDFinding struct {
	Reason string
	Detail string
}

// CVDResult 是审计结果。
type CVDResult struct {
	Safe bool
	Findings []CVDFinding
}

func CVDLower(x string) string {
	return x
}

func CVDIn(list []string, v string) bool {
	for _, x := range list { if CVDLower(x) == v { return true } }
	return false
}

func CVDSplit(in string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(in); i++ {
		end := i == len(in)
		sep := false
		if !end { c := in[i]; sep = c == ' ' || c == '\t' || c == '\n' || c == '\r' }
		if end || sep {
			if start >= 0 { out = append(out, in[start:i]); start = -1 }
		} else if start < 0 {
			start = i
		}
	}
	return out
}

func CVDKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// CVDHas 判定结果是否含某原因。
func CVDHas(r CVDResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// CVDAudit 审计输入字符串。
func CVDAudit(in string) CVDResult {
	res := CVDResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, CVDFinding{Reason: CVDReasonEmpty}); return res }
	toks := CVDSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := CVDLower(tok)
		key := cmp
		switch {
		case CVDIn(CVDBlock, key):
			res.Findings = append(res.Findings, CVDFinding{Reason: CVDReasonBlock, Detail: key})
		case CVDIn(CVDWarn, key):
			res.Findings = append(res.Findings, CVDFinding{Reason: CVDReasonWarn, Detail: key})
		}
		for i, lit := range CVDPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, CVDFinding{Reason: CVDPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
