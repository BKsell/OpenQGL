package main

// systemdlldirectoryguard.go —— Windows 系统 DLL 与已知易劫持库目录。
//
// 威胁模型：
//   原生库释放/加载需区分真正的系统 DLL（只应从 System32 加载）与已知易被 DLL 搜索顺序劫持的库，
//   防止把同名恶意库放到游戏目录被加载。纯字符查表，不用正则。

const (
	SDDClassBlock   = "block"
	SDDClassWarn    = "warn"
	SDDClassAllow   = "allow"
	SDDClassUnknown = "unknown"
)

var SDDBlock = []string{
	"version.dll",
	"winhttp.dll",
	"wininet.dll",
	"ws2_32.dll",
	"wsock32.dll",
	"crypt32.dll",
	"cryptbase.dll",
	"cryptsp.dll",
	"cryptnet.dll",
	"ncrypt.dll",
	"bcrypt.dll",
	"secur32.dll",
	"schannel.dll",
	"sspicli.dll",
	"user32.dll",
	"kernel32.dll",
	"kernelbase.dll",
	"advapi32.dll",
	"gdi32.dll",
	"gdiplus.dll",
	"comctl32.dll",
	"comdlg32.dll",
	"shell32.dll",
	"shlwapi.dll",
	"shcore.dll",
	"ole32.dll",
	"oleaut32.dll",
	"activeds.dll",
	"adsldp.dll",
	"adsldpc.dll",
	"uxtheme.dll",
	"dwmapi.dll",
	"dbghelp.dll",
	"dbgcore.dll",
	"psapi.dll",
	"mscoree.dll",
	"mscorwks.dll",
	"clr.dll",
	"clrjit.dll",
	"hostpolicy.dll",
	"coreclr.dll",
	"msvcr100.dll",
	"msvcp100.dll",
	"msvcr120.dll",
	"msvcp120.dll",
	"vcruntime140.dll",
	"vcruntime140_1.dll",
	"msvcp140.dll",
	"ucrtbase.dll",
	"msvcrt.dll",
	"msvcp60.dll",
	"mfc42.dll",
	"mfc140u.dll",
	"ntdll.dll",
	"win32u.dll",
	"winmm.dll",
	"imm32.dll",
	"msctf.dll",
	"oleacc.dll",
	"propsys.dll",
	"rpcrt4.dll",
	"iphlpapi.dll",
	"setupapi.dll",
	"cfgmgr32.dll",
	"powrprof.dll",
	"userenv.dll",
	"wtsapi32.dll",
	"wintrust.dll",
	"softpub.dll",
	"mssign32.dll",
	"imagehlp.dll",
	"authz.dll",
	"cabinet.dll",
	"msi.dll",
	"riched20.dll",
	"msftedit.dll",
	"urlmon.dll",
	"winspool.drv",
	"winscard.dll",
	"hid.dll",
	"newdev.dll",
	"devobj.dll",
	"dxgi.dll",
	"d3d11.dll",
	"opengl32.dll",
	"glu32.dll",
	"xinput1_4.dll",
	"dinput8.dll",
	"dsound.dll",
	"xaudio2_9.dll",
	"mfplat.dll",
	"mf.dll",
	"mfreadwrite.dll",
	"avrt.dll",
}

var SDDWarn = []string{
	"apphelp.dll",
	"windows.storage.dll",
	"shellstyle.dll",
	"iertutil.dll",
	"windows.web.dll",
	"actxprxy.dll",
	"browcli.dll",
	"cscapi.dll",
	"dui70.dll",
	"combase.dll",
	"comsvcs.dll",
	"mshtml.dll",
	"jscript.dll",
	"jscript9.dll",
	"vbscript.dll",
	"scrrun.dll",
	"wshom.ocx",
	"msxml3.dll",
	"msxml6.dll",
	"xmllite.dll",
	"winxml.dll",
	"normaliz.dll",
	"profapi.dll",
	"kernel.appcore.dll",
	"msv1_0.dll",
	"samsrv.dll",
	"netlogon.dll",
	"schannelext.dll",
	"webservices.dll",
	"dnsapi.dll",
	"mswsock.dll",
	"nsi.dll",
	"dhcpcsvc.dll",
	"dhcpcsvc6.dll",
	"winrnr.dll",
	"napinsp.dll",
	"pnrpnsp.dll",
	"wshbth.dll",
	"fwpuclnt.dll",
	"nlaapi.dll",
	"ncsi.dll",
}

var SDDAllow = []string{
	"fxsst.dll",
	"kbdus.dll",
	"kbdfr.dll",
	"kbdgr.dll",
	"kbdjpn.dll",
	"kbdkor.dll",
	"input.dll",
	"msadomd.dll",
	"msador15.dll",
	"msado15.dll",
	"msxmlr.dll",
	"vds_ps.dll",
	"wbemcomn.dll",
	"wbemdisp.dll",
	"wmiutils.dll",
	"ntshrui.dll",
	"srclient.dll",
	"cscui.dll",
	"cscobj.dll",
	"efswrt.dll",
	"windows.networking.dll",
	"windows.devices.dll",
	"windows.graphics.dll",
	"twinapi.appcore.dll",
	"twinapi.dll",
	"msasn1.dll",
	"msimg32.dll",
	"winmmbase.dll",
	"msv1_16.dll",
}

func SDDLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SDDIn(list []string, v string) bool {
	for _, x := range list { if SDDLower(x) == v { return true } }
	return false
}

// SDDClassify 分类单个令牌。
func SDDClassify(tok string) string {
	v := SDDLower(tok)
	switch {
	case SDDIn(SDDBlock, v): return SDDClassBlock
	case SDDIn(SDDWarn, v): return SDDClassWarn
	case SDDIn(SDDAllow, v): return SDDClassAllow
	default: return SDDClassUnknown
	}
}
