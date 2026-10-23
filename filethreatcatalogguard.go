package main

// filethreatcatalogguard.go —— 落盘文件名/扩展名/MIME 的威胁目录与分类守卫。
//
// 背景：
//   启动器会下载/解包/写入大量文件：整合包（mrpack）、mod（jar）、资源包、原生库、存档、
//   服务器图标、头像皮肤、JRE 安装包等。文件名来自远端清单或压缩包条目，可能：
//     - 使用可执行/脚本/快捷方式扩展名诱导用户双击（.exe .scr .lnk .js .jar ...）；
//     - 双扩展伪装（invoice.pdf.exe、photo.jpg .js）；
//     - 命中 Windows 保留设备名（CON、NUL、AUX、PRN、COM1..LPT9）导致写入异常/解析歧义；
//     - 尾部点/空格在 Windows 被剥离造成扩展名误判（evil.exe.）；
//     - 扩展名与声明的 MIME/Content-Type 不一致（MIME 混淆）；
//     - 文件名夹带控制字符、路径分隔符、ADS 冒号、通配符等。
//   本模块只做纯判定与目录查询，不触碰磁盘，不使用正则。所有比较走手写小写归一。

// FTC 风险等级。
const (
	FTCClassSafe       = "safe"       // 明确允许的数据/资源类型
	FTCClassArchive    = "archive"    // 压缩/打包，需要进一步解压审计
	FTCClassMacro      = "macrodoc"   // 可携带宏的办公文档
	FTCClassScript     = "script"     // 脚本，双击可能执行
	FTCClassShortcut   = "shortcut"   // 快捷方式/链接，可指向任意外部目标
	FTCClassExecutable = "executable" // 本机可执行/库
	FTCClassBlocked    = "blocked"    // 明确禁止落盘
)

// FTC 审计原因。
const (
	FTCReasonExecutableExt      = "filename-uses-executable-extension"
	FTCReasonScriptExt          = "filename-uses-script-extension"
	FTCReasonShortcutExt        = "filename-uses-shortcut-extension"
	FTCReasonMacroDoc           = "office-document-may-contain-macros"
	FTCReasonDoubleExtension     = "filename-uses-multiple-decorative-extensions"
	FTCReasonReservedDeviceName = "filename-is-windows-reserved-device-name"
	FTCReasonTrailingDotSpace   = "filename-ends-with-dot-or-space"
	FTCReasonControlCharacter   = "filename-contains-control-character"
	FTCReasonPathSeparator      = "filename-contains-path-separator"
	FTCReasonAdsColon           = "filename-contains-alternate-data-stream-colon"
	FTCReasonWildcard           = "filename-contains-wildcard-character"
	FTCReasonEmptyName          = "filename-is-empty"
	FTCReasonMimeMismatch       = "extension-mime-content-type-mismatch"
	FTCReasonUnknownExt         = "extension-has-no-known-content-policy"
)

// FTCExecutableExts 是本机可执行/可加载二进制扩展名（小写、含点）。
var FTCExecutableExts = []string{
	".exe", ".dll", ".sys", ".scr", ".com", ".drv", ".ocx", ".cpl", ".msi",
	".msp", ".mst", ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".ps2", ".vbs",
	".vbe", ".js", ".jse", ".ws", ".wsf", ".wsh", ".jar", ".app", ".appimage",
	".deb", ".rpm", ".apk", ".aab", ".ipa", ".action", ".bin", ".run", ".out",
	".elf", ".so", ".dylib", ".a", ".lib", ".exp", ".pif", ".gadget", ".hta",
	".csh", ".bin", ".efi", ".fon", ".ins", ".isp", ".lnk", ".mad", ".maf",
	".mag", ".mam", ".maq", ".mar", ".mas", ".mat", ".mav", ".maw", ".mcf",
	".mda", ".mdb", ".mde", ".mdt", ".mdw", ".mdz", ".msc", ".msi", ".msp",
	".ops", ".pcd", ".ps1xml", ".psc1", ".pssc", ".reg", ".scf", ".shb",
	".shs", ".vb", ".vbe", ".vbp", ".vxd", ".ws", ".wsc", ".wsf", ".wsh",
	".xll", ".slk",
}

// FTCScriptExts 是脚本/解释器源码扩展名（双击或被宿主解释执行）。
var FTCScriptExts = []string{
	".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vbs", ".vbe", ".py",
	".pyw", ".rb", ".rbw", ".pl", ".pm", ".php", ".php3", ".php5", ".phtml",
	".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh", ".tcsh", ".lua", ".wlua",
	".au3", ".ahk", ".ps1", ".psm1", ".psd1", ".ps2", ".bat", ".cmd", ".jse",
	".wsf", ".wsh", ".hta", ".groovy", ".gradle", ".scala", ".clj", ".dart",
	".r", ".R", ".m", ".ml", ".nim", ".cr", ".ex", ".exs", ".erl", ".beam",
	".swift", ".wasm", ".wat", ".svg", ".xhtml", ".html", ".htm", ".xml",
	".xsl", ".xslt",
}

// FTCShortcutExts 是快捷方式/链接/容器跳转扩展名。
var FTCShortcutExts = []string{
	".lnk", ".url", ".desktop", ".webloc", ".alias", ".scf", ".mapimail",
	".pif", ".shb", ".shs", ".xnk", ". SettingContent-ms", ".appref-ms",
}

// FTCMacroDocExts 是可携带宏/活动内容的办公文档扩展名。
var FTCMacroDocExts = []string{
	".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam",
	".ppsm", ".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot", ".pps",
	".ppa", ".rtf", ".mht", ".mhtml", ".odt", ".ods", ".odp", ".odg", ".odf",
}

// FTCArchiveExts 是压缩/打包扩展名（允许落盘但必须再做解压审计）。
var FTCArchiveExts = []string{
	".zip", ".zipx", ".jar", ".war", ".ear", ".jar.pack", ".gz", ".tgz",
	".bz2", ".tbz2", ".xz", ".txz", ".zst", ".tzst", ".lz", ".lzma", ".tlz",
	".7z", ".rar", ".cab", ".msi", ".pkg", ".deb", ".rpm", ".apk", ".aab",
	".ipa", ".tar", ".ustar", ".cpio", ".arj", ".lha", ".lzh", ".ace", ".arc",
	".zoo", ".bz", ".tbz", ".tao", ".mar", ".mrpack", ".mcpack", ".mcworld",
	".mcaddon", ".mcgame", ".pak", ".pack", ".whl", ".egg", ".gem", ".tgz",
	".nupkg", ".appx", ".msix", ".snappy", ".hff", ".lzo", ".z",
}

// FTCReservedDeviceNames 是 Windows 保留设备名（不分大小写，去除扩展名后判定）。
var FTCReservedDeviceNames = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	"CONIN$", "CONOUT$",
}

// FTCMimeByExt 是扩展名到规范 MIME 的目录，用于检测 MIME 混淆。
var FTCMimeByExt = map[string]string{
	".html": "text/html", ".htm": "text/html", ".css": "text/css",
	".js": "text/javascript", ".mjs": "text/javascript", ".json": "application/json",
	".wasm": "application/wasm", ".xml": "application/xml", ".svg": "image/svg+xml",
	".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
	".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
	".ico": "image/x-icon", ".avif": "image/avif", ".apng": "image/apng",
	".tif": "image/tiff", ".tiff": "image/tiff", ".mp3": "audio/mpeg",
	".wav": "audio/wav", ".ogg": "audio/ogg", ".flac": "audio/flac",
	".m4a": "audio/mp4", ".aac": "audio/aac", ".opus": "audio/opus",
	".mp4": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime",
	".avi": "video/x-msvideo", ".mkv": "video/x-matroska", ".wmv": "video/x-ms-wmv",
	".zip": "application/zip", ".jar": "application/java-archive",
	".gz": "application/gzip", ".tgz": "application/gzip", ".bz2": "application/x-bzip2",
	".xz": "application/x-xz", ".zst": "application/zstd", ".7z": "application/x-7z-compressed",
	".rar": "application/vnd.rar", ".tar": "application/x-tar",
	".mrpack": "application/x-modrinth-modpack+zip", ".mcpack": "application/zip",
	".mcworld": "application/zip", ".mcaddon": "application/zip",
	".pdf": "application/pdf", ".txt": "text/plain", ".csv": "text/csv",
	".md": "text/markdown", ".log": "text/plain", ".properties": "text/plain",
	".toml": "application/toml", ".yaml": "text/yaml", ".yml": "text/yaml",
	".exe": "application/vnd.microsoft.portable-executable",
	".dll": "application/x-msdownload", ".msi": "application/x-msi",
	".lnk": "application/x-ms-shortcut", ".woff": "font/woff", ".woff2": "font/woff2",
	".ttf": "font/ttf", ".otf": "font/otf", ".eot": "application/vnd.ms-fontobject",
	".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xls": "application/vnd.ms-excel", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".ppt": "application/vnd.ms-powerpoint", ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

// FTCFinding 表示一个文件名/类型问题。
type FTCFinding struct {
	Reason string
	Detail string
}

// FTCResult 是审计结果。
type FTCResult struct {
	Safe      bool
	Base      string
	Ext       string
	Class     string
	Findings  []FTCFinding
}

// FTCLower 手写 ASCII 小写，避免依赖 unicode 表造成的意外归一。
func FTCLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// FTCLastExt 返回小写的最后一个扩展名（含点），无扩展名返回空串。
func FTCLastExt(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return FTCLower(name[i:])
		}
		if name[i] == '/' || name[i] == '\\' {
			break
		}
	}
	return ""
}

// FTCBaseName 去掉目录部分，返回最后一段文件名。
func FTCBaseName(p string) string {
	last := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '/' || p[i] == '\\' {
			last = i + 1
		}
	}
	return p[last:]
}

// FTCStripAllExts 返回去掉所有点分段后的主干，并统计扩展名段数。
func FTCStripAllExts(name string) (stem string, extCount int) {
	s := name
	for {
		dot := -1
		for i := 0; i < len(s); i++ {
			if s[i] == '.' {
				dot = i
				break
			}
		}
		if dot < 0 {
			return s, extCount
		}
		extCount++
		s = s[:dot]
	}
}

// FTCContainsString 在小写字符串切片中做精确包含判定。
func FTCContainsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// FTCClassifyExt 按目录给扩展名分类。
func FTCClassifyExt(ext string) string {
	e := FTCLower(ext)
	if FTCContainsString(FTCExecutableExts, e) {
		return FTCClassExecutable
	}
	if FTCContainsString(FTCShortcutExts, e) {
		return FTCClassShortcut
	}
	if FTCContainsString(FTCMacroDocExts, e) {
		return FTCClassMacro
	}
	if FTCContainsString(FTCScriptExts, e) {
		return FTCClassScript
	}
	if FTCContainsString(FTCArchiveExts, e) {
		return FTCClassArchive
	}
	if _, ok := FTCMimeByExt[e]; ok {
		return FTCClassSafe
	}
	return ""
}

// FTCStemReserved 判定去扩展名主干是否为 Windows 保留设备名。
func FTCStemReserved(stem string) bool {
	u := FTCLower(stem)
	for _, d := range FTCReservedDeviceNames {
		if u == FTCLower(d) {
			return true
		}
	}
	return false
}

// FTCAuditName 审计单个落盘文件名（只传文件名，不含目录）。
func FTCAuditName(rawName string) FTCResult {
	res := FTCResult{Base: FTCBaseName(rawName), Class: FTCClassSafe}
	name := res.Base
	res.Ext = FTCLastExt(name)
	if name == "" {
		res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonEmptyName})
		res.Safe = false
		return res
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 32 {
			res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonControlCharacter})
			break
		}
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '/' || name[i] == '\\' {
			res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonPathSeparator})
			break
		}
	}
	last := name[len(name)-1]
	if last == '.' || last == ' ' {
		res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonTrailingDotSpace})
	}
	// ADS 冒号：NTFS 交替数据流，且可截断真实扩展名。
	for i := 1; i < len(name); i++ {
		if name[i] == ':' {
			res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonAdsColon})
			break
		}
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '*' || name[i] == '?' {
			res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonWildcard})
			break
		}
	}
	stem, extCount := FTCStripAllExts(name)
	if FTCStemReserved(stem) {
		res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonReservedDeviceName})
	}
	if extCount >= 2 {
		res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonDoubleExtension})
	}
	cls := FTCClassifyExt(res.Ext)
	res.Class = cls
	switch cls {
	case FTCClassExecutable:
		res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonExecutableExt, Detail: res.Ext})
	case FTCClassShortcut:
		res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonScriptExt, Detail: res.Ext})
	case FTCClassScript:
		res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonScriptExt, Detail: res.Ext})
	case FTCClassMacro:
		res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonMacroDoc, Detail: res.Ext})
	}
	if cls == "" {
		res.Findings = append(res.Findings, FTCFinding{Reason: FTCReasonUnknownExt, Detail: res.Ext})
	}
	res.Safe = len(res.Findings) == 0
	return res
}

// FTCCheckMime 校验扩展名声明的 Content-Type 是否与目录一致（空声明不判）。
func FTCCheckMime(name, declaredMime string) (consistent bool, expected string) {
	ext := FTCLastExt(name)
	if ext == "" {
		return true, ""
	}
	want, ok := FTCMimeByExt[ext]
	if !ok {
		return true, ""
	}
	if declaredMime == "" {
		return true, want
	}
	if FTCLower(declaredMime) == want || FTCLower(declaredMime) == "application/octet-stream" {
		return true, want
	}
	return false, want
}

// FTCHas 判定结果是否含某原因。
func FTCHas(r FTCResult, reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
