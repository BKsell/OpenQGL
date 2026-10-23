package main

// dlfilenameguard.go —— 下载响应 Content-Disposition 文件名净化守卫。
//
// 背景：
//   启动器下载 mod/资源/版本文件时常用服务器给的文件名落盘。该名来自响应头，是攻击者可控输入：
//     - 路径穿越：../../AppData/Roaming/.minecraft/mods/x.jar 覆盖既有文件；
//     - 绝对路径/盘符/UNC：C:\Windows\...、\\?\、\\host\share；
//     - Windows 保留设备名：CON、PRN、AUX、NUL、COM1-9、LPT1-9（会写到设备而非文件）；
//     - 末尾空格/点被 Win32 路径规范化吞掉，可绕过扩展名/名字校验；
//     - NTFS 备用数据流 a.jar:evil、NTFS 8.3 短名混淆；
//     - NUL/控制字符、CR/LF 头注入；RFC5987 filename*=UTF-8''%2e%2e 编码穿越；
//     - 伪装扩展名（.jar.exe 双扩展、polyglot 由 polyglotguard/mimesniffguard 另管）。
//   本模块产出一个"净化后的安全落盘名 + 结论"，纯字符处理，百分号解码自实现，不使用正则。

import "strings"

const (
	DLFReasonPathTraversal      = "dlfilename-path-traversal"
	DLFReasonAbsolutePath       = "dlfilename-absolute-or-unc-path"
	DLFReasonReservedDevice     = "dlfilename-windows-reserved-device"
	DLFReasonTrailingSpaceDot   = "dlfilename-trailing-space-or-dot"
	DLFReasonADS                = "dlfilename-ntfs-alternate-data-stream"
	DLFReasonControlChar        = "dlfilename-control-character"
	DLFReasonHeaderCRLF         = "dlfilename-header-crlf-injection"
	DLFReasonBadPercentEncoding = "dlfilename-bad-percent-encoding"
	DLFReasonEmptyAfterClean    = "dlfilename-empty-after-sanitization"
	DLFReasonExtensionDenied    = "dlfilename-extension-not-allowed"
)

// DLFPolicy 设定文件名策略。
type DLFPolicy struct {
	AllowedExtensions map[string]bool // 空表示不限制
	FallbackName      string
}

// DLFFinding 记录一处文件名风险。
type DLFFinding struct {
	Reason string
	Detail string
}

// DefaultDLFPolicy 允许常见 Minecraft/资源类型。
func DefaultDLFPolicy() DLFPolicy {
	return DLFPolicy{
		AllowedExtensions: map[string]bool{
			".jar": true, ".zip": true, ".mrpack": true, ".png": true, ".json": true,
			".txt": true, ".toml": true, ".mcpack": true, ".mcaddon": true, ".nbt": true,
		},
		FallbackName: "download.bin",
	}
}

var dlfReservedDevices = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// dlfHexVal 返回十六进制字符的值。
func dlfHexVal(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

// dlfPercentDecode 仅做 RFC5987/标准百分号解码（UTF-8 字节原样保留）。
func dlfPercentDecode(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, true
	}
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) {
				return "", false
			}
			hi, ok1 := dlfHexVal(s[i+1])
			lo, ok2 := dlfHexVal(s[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			b = append(b, byte(hi<<4|lo))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return string(b), true
}

// DLFSanitize 解析可能来自 filename / filename* 的值，输出安全基名与风险。
func DLFSanitize(rawName string, policy DLFPolicy) (base string, safe bool, findings []DLFFinding) {
	name := strings.TrimSpace(rawName)
	if strings.ContainsAny(name, "\r\n") {
		findings = append(findings, DLFFinding{Reason: DLFReasonHeaderCRLF})
		name = strings.NewReplacer("\r", "", "\n", "").Replace(name)
	}
	if strings.Contains(strings.ToLower(name), "=") && strings.Contains(name, "'") {
		// 形如 UTF-8'en'name，剥掉 charset'lang' 前缀
		if i1 := strings.IndexByte(name, '\''); i1 >= 0 {
			if i2 := strings.IndexByte(name[i1+1:], '\''); i2 >= 0 {
				name = name[i1+1+i2+1:]
			}
		}
	}
	decoded, ok := dlfPercentDecode(name)
	if !ok {
		findings = append(findings, DLFFinding{Reason: DLFReasonBadPercentEncoding})
	} else {
		name = decoded
	}

	// 控制字符
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x20 || c == 0x7F {
			findings = append(findings, DLFFinding{Reason: DLFReasonControlChar})
			break
		}
	}

	// 绝对路径 / UNC / 盘符 / 穿越
	slashed := strings.ReplaceAll(name, "/", "\\")
	if strings.Contains(slashed, "..") {
		findings = append(findings, DLFFinding{Reason: DLFReasonPathTraversal})
	}
	if strings.HasPrefix(slashed, `\\`) {
		findings = append(findings, DLFFinding{Reason: DLFReasonAbsolutePath, Detail: "unc"})
	}
	// 去掉所有目录分量，只保留基名
	if idx := strings.LastIndexByte(slashed, '\\'); idx >= 0 {
		if idx > 0 {
			findings = append(findings, DLFFinding{Reason: DLFReasonPathTraversal, Detail: "has-dir"})
		}
		slashed = slashed[idx+1:]
	}
	if len(slashed) >= 2 && slashed[1] == ':' {
		findings = append(findings, DLFFinding{Reason: DLFReasonAbsolutePath, Detail: "drive"})
		if i := strings.IndexByte(slashed, '\\'); i >= 0 {
			slashed = slashed[i+1:]
		}
	}

	// ADS
	if i := strings.IndexByte(slashed, ':'); i > 0 {
		findings = append(findings, DLFFinding{Reason: DLFReasonADS})
		slashed = slashed[:i]
	}

	// 末尾空格/点
	if strings.HasSuffix(slashed, " ") || strings.HasSuffix(slashed, ".") {
		findings = append(findings, DLFFinding{Reason: DLFReasonTrailingSpaceDot})
	}
	slashed = strings.TrimRight(slashed, " .")

	// 保留设备名（去掉扩展名后判定）
	stem := slashed
	if i := strings.LastIndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if dlfReservedDevices[strings.ToLower(stem)] {
		findings = append(findings, DLFFinding{Reason: DLFReasonReservedDevice})
	}

	if slashed == "" || dlfReservedDevices[strings.ToLower(stem)] {
		slashed = policy.FallbackName
		if slashed == "" {
			slashed = "download.bin"
		}
		findings = append(findings, DLFFinding{Reason: DLFReasonEmptyAfterClean})
	}

	// 扩展名白名单
	ext := strings.ToLower(filepathExtDLF(slashed))
	if len(policy.AllowedExtensions) > 0 && ext != "" && !policy.AllowedExtensions[ext] {
		findings = append(findings, DLFFinding{Reason: DLFReasonExtensionDenied, Detail: ext})
	}
	return slashed, len(findings) == 0, findings
}

// filepathExtDLF 返回含点的扩展名（小写由调用方处理）。
func filepathExtDLF(name string) string {
	for i := len(name) - 1; i >= 0 && name[i] != '/' && name[i] != '\\'; i-- {
		if name[i] == '.' {
			if i == 0 {
				return ""
			}
			return name[i:]
		}
	}
	return ""
}
