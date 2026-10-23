package main

// windowsprocessdirectoryguard.go —— Windows 进程映像名风险目录。
//
// 威胁模型：
//   启动器/子进程解析 PATH 或拼接进程名时需识别：系统关键进程（防仿冒/结束）、常被滥用的 LOLBin 与脚本宿主
//   需复核、常规工具可放行。纯字符查表，不用正则。

// PRD 风险类别。
const (
	PRDClassBlock = "block"
	PRDClassWarn  = "warn"
	PRDClassAllow = "allow"
)

const (
	PRDReasonBlock   = "prd-input-hits-blocked-catalog"
	PRDReasonWarn    = "prd-input-hits-review-catalog"
	PRDReasonPrefix  = "prd-input-hits-dangerous-prefix"
	PRDReasonEmpty   = "prd-input-is-empty"
)

var PRDBlock = []string{
	"csrss.exe",
	"wininit.exe",
	"services.exe",
	"lsass.exe",
	"lsm.exe",
	"smss.exe",
	"winlogon.exe",
	"ntoskrnl.exe",
	"ntkrnlmp.exe",
	"hal.dll",
	"svchost.exe",
	"dwm.exe",
	"spoolsv.exe",
	"system",
	"system idle process",
	"registry",
	"memory compression",
	"secure system",
	"msmpeng.exe",
	"nissrv.exe",
	"mpcmdrun.exe",
	"securityhealthservice.exe",
	"securityhealthsystray.exe",
	"wudfhost.exe",
	"csrsys.exe",
	"fontdrvhost.exe",
	"sihost.exe",
	"taskhostw.exe",
	"runtimebroker.exe",
}

var PRDWarn = []string{
	"cmd.exe",
	"powershell.exe",
	"pwsh.exe",
	"wscript.exe",
	"cscript.exe",
	"mshta.exe",
	"rundll32.exe",
	"regsvr32.exe",
	"regasm.exe",
	"regsvc.exe",
	"msbuild.exe",
	"installutil.exe",
	"csc.exe",
	"csi.exe",
	"dnx.exe",
	"dotnet.exe",
	"msxsl.exe",
	"ieexec.exe",
	"dfsvc.exe",
	"presentationhost.exe",
	"forfiles.exe",
	"wmic.exe",
	"wmic",
	"schtasks.exe",
	"at.exe",
	"sc.exe",
	"net.exe",
	"net1.exe",
	"netsh.exe",
	"reg.exe",
	"regedit.exe",
	"regedt32.exe",
	"certutil.exe",
	"certreq.exe",
	"bitsadmin.exe",
	"esentutl.exe",
	"expand.exe",
	"extrac32.exe",
	"makecab.exe",
	"msiexec.exe",
	"msinfo32.exe",
	"mavinject.exe",
	"pcalua.exe",
	"pcwrun.exe",
	"syncappvpublishingserver.exe",
	"verclsid.exe",
	"wsreset.exe",
	"xcopy.exe",
	"robocopy.exe",
	"ftp.exe",
	"tftp.exe",
	"telnet.exe",
	"curl.exe",
	"wget.exe",
	"tar.exe",
	"cipher.exe",
	"takeown.exe",
	"icacls.exe",
	"attrib.exe",
	"vssadmin.exe",
	"wbadmin.exe",
	"bcdedit.exe",
	"diskpart.exe",
	"mountvol.exe",
	"fsutil.exe",
	"subst.exe",
	"mklink",
	"wevtutil.exe",
	"eventcreate.exe",
	"nltest.exe",
	"dsquery.exe",
	"klist.exe",
	"runas.exe",
	"wsl.exe",
	"bash.exe",
	"conhost.exe",
	"openfiles.exe",
	"replace.exe",
	"debug.exe",
	"edit.com",
	"print.exe",
	"lpr.exe",
	"finger.exe",
	"rexec.exe",
	"rsh.exe",
	"msdt.exe",
	"control.exe",
	"mmc.exe",
	"explorer.exe",
	"browserbroker.exe",
	"searchindexer.exe",
	"searchprotocolhost.exe",
	"searchfilterhost.exe",
	"dllhost.exe",
	"dfrgui.exe",
	"cleanmgr.exe",
	"resmon.exe",
	"perfmon.exe",
	"rekeywiz.exe",
	"credwiz.exe",
}

var PRDAllow = []string{
	"notepad.exe",
	"calc.exe",
	"write.exe",
	"wordpad.exe",
	"mspaint.exe",
	"snippingtool.exe",
	"screenclippinghost.exe",
	"charmap.exe",
	"magnify.exe",
	"narrator.exe",
	"osk.exe",
	"utilman.exe",
	"displayswitch.exe",
	"dxdiag.exe",
	"winver.exe",
	"where.exe",
	"whoami.exe",
	"hostname.exe",
	"systeminfo.exe",
	"ver.exe",
	"vol.exe",
	"label.exe",
	"date.exe",
	"time.exe",
	"sort.exe",
	"more.com",
	"find.exe",
	"findstr.exe",
	"tree.com",
	"choice.com",
	"clip.exe",
	"echo.exe",
	"type.exe",
	"tasklist.exe",
	"taskkill.exe",
	"quser.exe",
	"query.exe",
	"qwinsta.exe",
	"logoff.exe",
	"shutdown.exe",
	"psr.exe",
	"w32tm.exe",
	"ipconfig.exe",
	"ping.exe",
	"tracert.exe",
	"pathping.exe",
	"route.exe",
	"arp.exe",
	"getmac.exe",
	"nslookup.exe",
	"netstat.exe",
	"test-netconnection",
	"resolve-dnsname",
	"go.exe",
	"python.exe",
	"python3.exe",
	"node.exe",
	"npm.cmd",
	"npx.cmd",
	"git.exe",
	"code.exe",
	"devenv.exe",
	"7z.exe",
	"7zfm.exe",
	"winrar.exe",
	"javaw.exe",
	"java.exe",
	"javaws.exe",
}

var PRDPrefixLit = []string{
}
var PRDPrefixReason = []string{
}

// PRDFinding 表示一条命中。
type PRDFinding struct {
	Reason string
	Detail string
}

// PRDResult 是审计结果。
type PRDResult struct {
	Safe bool
	Findings []PRDFinding
}

func PRDLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func PRDIn(list []string, v string) bool {
	for _, x := range list { if PRDLower(x) == v { return true } }
	return false
}

func PRDSplit(in string) []string {
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

func PRDKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// PRDHas 判定结果是否含某原因。
func PRDHas(r PRDResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// PRDAudit 审计输入字符串。
func PRDAudit(in string) PRDResult {
	res := PRDResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, PRDFinding{Reason: PRDReasonEmpty}); return res }
	toks := PRDSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := PRDLower(tok)
		key := cmp
		switch {
		case PRDIn(PRDBlock, key):
			res.Findings = append(res.Findings, PRDFinding{Reason: PRDReasonBlock, Detail: key})
		case PRDIn(PRDWarn, key):
			res.Findings = append(res.Findings, PRDFinding{Reason: PRDReasonWarn, Detail: key})
		}
		for i, lit := range PRDPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, PRDFinding{Reason: PRDPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
