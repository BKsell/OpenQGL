package main

// registrypathdirectoryguard.go —— Windows 注册表敏感键路径目录。
//
// 威胁模型：
//   自启动、映像劫持、AppInit_DLLs、Winlogon Shell、防御器排除项等键被改写即持久化/绕过。本目录登记
//   敏感键路径片段，纯字符查表，不读注册表，不用正则。

// WRD 风险类别。
const (
	WRDClassBlock = "block"
	WRDClassWarn  = "warn"
	WRDClassAllow = "allow"
)

const (
	WRDReasonBlock   = "wrd-input-hits-blocked-catalog"
	WRDReasonWarn    = "wrd-input-hits-review-catalog"
	WRDReasonPrefix  = "wrd-input-hits-dangerous-prefix"
	WRDReasonEmpty   = "wrd-input-is-empty"
)

var WRDBlock = []string{
	"CurrentVersion\\Run",
	"CurrentVersion\\RunOnce",
	"CurrentVersion\\RunOnceEx",
	"CurrentVersion\\RunServices",
	"CurrentVersion\\RunServicesOnce",
	"CurrentVersion\\Winlogon",
	"CurrentVersion\\Windows",
	"CurrentVersion\\Explorer\\User Shell Folders",
	"CurrentVersion\\Explorer\\Shell Folders",
	"CurrentVersion\\Policies\\Explorer\\Run",
	"CurrentVersion\\Image File Execution Options",
	"Image File Execution Options",
	"CurrentVersion\\App Paths",
	"CurrentVersion\\Applets",
	"CurrentVersion\\App Management",
	"CurrentVersion\\BootRun",
	"CurrentVersion\\Policies\\System",
	"CurrentVersion\\Policies\\Explorer",
	"CurrentVersion\\ShellCompatibility",
	"Software\\Microsoft\\Windows\\CurrentVersion\\Windows",
	"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
	"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
	"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
	"Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
	"Winlogon",
	"AppInit_DLLs",
	"AppInit_DLLs2",
	"LoadAppInit_DLLs",
	"RequireSignedAppInit_DLLs",
	"Userinit",
	"Shell",
	"Taskman",
	"UIHost",
	"VmApplet",
	"AppSetup",
	"GinaDLL",
	"Notification Packages",
	"Security Packages",
	"Authentication Packages",
	"BootExecute",
	"ServiceDll",
	"ImagePath",
	"Start",
	"DllName",
	"Debugger",
	"GlobalFlag",
	"SilentProcessExit",
	"MonitorProcess",
	"KnownDlls",
	"KnownDllPath",
	"WinSock2",
	"NameSpace_Catalog5",
	"Protocol_Catalog9",
	"Winsock2",
	"Winsock",
	"LSA",
	"Security Providers",
	"SafeDllSearchMode",
	"AlwaysInstallElevated",
	"RunAsPPL",
	"StartService",
	"Control\\Session Manager\\AppCertDlls",
	"Control\\Session Manager\\BootExecute",
	"Control\\Session Manager\\KnownDLLs",
	"Control\\Lsa\\Security Packages",
	"Control\\Lsa\\Authentication Packages",
	"Control\\Lsa\\Notification Packages",
	"Control\\Lsa\\Security Providers",
	"Control\\SecurityProviders\\SecurityProviders",
	"Control\\Print\\Environments",
	"Control\\Print\\Monitors",
	"Control\\NetworkProvider\\Order",
	"Control\\Class",
	"Control\\CriticalDeviceDatabase",
	"Control\\ServiceGroupOrder",
	"Control\\ServiceProvider",
	"Services",
	"WinDefend",
	"MsMpSvc",
	"ExclusionPaths",
	"ExclusionExtensions",
	"ExclusionProcesses",
	"DisableAntiSpyware",
	"DisableAntiVirus",
	"DisableRealtimeMonitoring",
	"DisableRoutinelyTakingAction",
	"SpynetReporting",
	"SubmitSamplesConsent",
	"Real-Time Protection",
	"WUDFServices",
	"Windows Defender",
	"Defender",
}

var WRDWarn = []string{
	"CurrentVersion\\Internet Settings",
	"CurrentVersion\\Internet Settings\\ZoneMap",
	"CurrentVersion\\Internet Settings\\Zones",
	"CurrentVersion\\ProxyServer",
	"ProxyEnable",
	"ProxyServer",
	"ProxyOverride",
	"AutoConfigURL",
	"CurrentVersion\\Explorer\\Advanced",
	"CurrentVersion\\Explorer\\FileExts",
	"CurrentVersion\\Explorer\\MountPoints2",
	"CurrentVersion\\Explorer\\StartPage",
	"CurrentVersion\\Uninstall",
	"CurrentVersion\\Installer",
	"CurrentVersion\\DevicePath",
	"CurrentVersion\\DevicePath2",
	"CurrentVersion\\Policies",
	"CurrentVersion\\Group Policy",
	"CurrentVersion\\Schedule\\TaskCache",
	"ScheduledTask",
	"TaskCache\\Tree",
	"TaskCache\\Tasks",
	"Software\\Classes",
	"Classes\\.exe",
	"Classes\\exefile",
	"Classes\\.js",
	"Classes\\JSFile",
	"Classes\\.vbs",
	"Classes\\VBSFile",
	"Classes\\http",
	"Classes\\https",
	"Classes\\mailto",
	"Classes\\AppID",
	"Classes\\CLSID",
	"Classes\\Interface",
	"Classes\\TypeLib",
	"Classes\\Applications",
	"Classes\\AllFilesystemObjects",
	"Classes\\Directory",
	"Classes\\Folder",
	"Classes\\Drive",
	"Classes\\Protocols",
	"Protocols\\Handler",
	"Protocols\\Filter",
	"Classes\\mscfile",
	"Classes\\cmdfile",
	"Classes\\batfile",
	"Classes\\comfile",
	"Classes\\piffile",
	"Classes\\scrfile",
	"Classes\\lnkfile",
	"Classes\\Inkfile",
	"Software\\Policies",
	"Policies\\Microsoft\\Windows\\System",
	"Policies\\Microsoft\\Windows Defender",
	"Policies\\Microsoft\\Edge",
	"Policies\\Google\\Chrome",
	"StartupApproved",
	"StartupFolder",
}

var WRDAllow = []string{
	"CurrentVersion\\Theme",
	"CurrentVersion\\Themes",
	"CurrentVersion\\Fonts",
	"CurrentVersion\\FontManagement",
	"CurrentVersion\\DateTime",
	"CurrentVersion\\DateTime\\Servers",
	"CurrentVersion\\LanguagePack",
	"CurrentVersion\\LanguageProfile",
	"CurrentVersion\\Keyboard Layout",
	"CurrentVersion\\Keyboard Layouts",
	"CurrentVersion\\UserData",
	"CurrentVersion\\Setup",
	"CurrentVersion\\ProductId",
	"CurrentVersion\\RegisteredOwner",
	"CurrentVersion\\RegisteredOrganization",
	"CurrentVersion\\Build",
	"CurrentVersion\\BuildLab",
	"CurrentVersion\\BuildLabEx",
	"CurrentVersion\\CurrentVersion",
	"CurrentVersion\\EditionID",
	"CurrentVersion\\InstallationType",
	"CurrentVersion\\ProductName",
	"CurrentVersion\\ReleaseId",
	"CurrentVersion\\UBR",
	"CurrentVersion\\PathName",
	"CurrentVersion\\ProgramFilesDir",
	"CurrentVersion\\ProgramFilesPath",
	"CurrentVersion\\CommonFilesDir",
	"CurrentVersion\\MediaPath",
	"CurrentVersion\\SM_Games",
	"CurrentVersion\\SM_ConfigurePrograms",
	"CurrentVersion\\SM_AccessoriesName",
}

var WRDPrefixLit = []string{
}
var WRDPrefixReason = []string{
}

// WRDFinding 表示一条命中。
type WRDFinding struct {
	Reason string
	Detail string
}

// WRDResult 是审计结果。
type WRDResult struct {
	Safe bool
	Findings []WRDFinding
}

func WRDLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func WRDIn(list []string, v string) bool {
	for _, x := range list { if WRDLower(x) == v { return true } }
	return false
}

func WRDSplit(in string) []string {
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

func WRDKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// WRDHas 判定结果是否含某原因。
func WRDHas(r WRDResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// WRDAudit 审计输入字符串。
func WRDAudit(in string) WRDResult {
	res := WRDResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, WRDFinding{Reason: WRDReasonEmpty}); return res }
	toks := WRDSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := WRDLower(tok)
		key := cmp
		switch {
		case WRDIn(WRDBlock, key):
			res.Findings = append(res.Findings, WRDFinding{Reason: WRDReasonBlock, Detail: key})
		case WRDIn(WRDWarn, key):
			res.Findings = append(res.Findings, WRDFinding{Reason: WRDReasonWarn, Detail: key})
		}
		for i, lit := range WRDPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, WRDFinding{Reason: WRDPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
