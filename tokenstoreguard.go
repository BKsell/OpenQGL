package main

// tokenstoreguard.go —— 登录令牌/凭据在本地落盘的存储安全守卫。
//
// 背景：
//   启动器拿到微软/Mojang/Yggdrasil 的 access_token/refresh_token 后需要持久化以便免登录。
//   落盘环节常见错误：
//     - 明文 JSON/INI 存 token，同机任意程序/备份/同步盘/杀软扫描都能读；
//     - 文件权限继承为 Users 可读，或放在共享目录/临时目录；
//     - 写入用 0644/0777，或先落到世界可读临时文件再 rename（存在可读窗口）；
//     - 留下 .bak/.old/~ 副本、crash dump、日志里仍含 token；
//     - 没用系统保护（Windows DPAPI / 钥匙串/keyring）或至少用户范围加密；
//     - refresh_token 与 access_token 同文件明文，泄露后可长期续期。
//   本模块对"一个凭据存储视图"做判定（由调用方从真实文件/键值存储映射），纯字符串/布尔/位
//   运算，不使用正则。本地用途完整性建议结合 UMFS，不改变外部 API 哈希算法。

import "strings"

const (
	TKSReasonPlaintextToken       = "tokenstore-plaintext-token"
	TKSReasonWorldReadable        = "tokenstore-world-readable-file"
	TKSReasonInsecurePermissions  = "tokenstore-insecure-permission-bits"
	TKSReasonSharedOrTempLocation = "tokenstore-shared-or-temp-location"
	TKSReasonBackupCopyLeak       = "tokenstore-backup-or-temp-copy"
	TKSReasonNoOSProtection       = "tokenstore-no-os-protection"
	TKSReasonRefreshAlongside     = "tokenstore-refresh-token-alongside-access"
	TKSReasonSensitiveInFilename  = "tokenstore-sensitive-filename"
	TKSReasonWorldWritable        = "tokenstore-world-writable-file"
)

// TKSPolicy 设定存储要求。
type TKSPolicy struct {
	RequireOSProtection    bool // DPAPI/keyring 或用户范围加密
	ForbidRefreshAlongside bool
	MaxAllowedPermBits     uint32 // 允许的最大 POSIX 权限位（默认 0600）
}

// TKSSiteView 描述一个凭据存储位置/文件。
type TKSSiteView struct {
	Path              string
	ContainsToken     bool   // 文件内容中是否出现明文 token 字段
	PermBits          uint32 // POSIX 风格权限位（Windows 下用等效 ACL 映射）
	InSharedOrTemp    bool   // ProgramData / /tmp / 公共目录 / 同步盘
	IsBackupOrTemp    bool   // .bak/.old/~/.tmp/crash 报告
	OSProtected       bool   // 是否经 DPAPI/keyring/用户范围加密
	HoldsAccess       bool
	HoldsRefresh      bool
	FilenameSensitive bool // 文件名直接含 token/password/credential
}

// TKSFinding 记录一处存储风险。
type TKSFinding struct {
	Reason string
	Detail string
}

// DefaultTKSPolicy 要求系统级保护、禁止 refresh 与 access 同处明文、权限不宽于 0600。
func DefaultTKSPolicy() TKSPolicy {
	return TKSPolicy{
		RequireOSProtection:    true,
		ForbidRefreshAlongside: true,
		MaxAllowedPermBits:     0o600,
	}
}

// tksPathBase 取文件名（兼容两种分隔符）。
func tksPathBase(p string) string {
	s := strings.ReplaceAll(p, "/", "\\")
	if idx := strings.LastIndexByte(s, '\\'); idx >= 0 {
		s = s[idx+1:]
	}
	return strings.ToLower(s)
}

// tksBackupLike 判断文件名是否像备份/临时/转储副本。
func tksBackupLike(base string) bool {
	suffixes := []string{".bak", ".old", ".orig", ".tmp", ".temp", ".swp", "~",
		".log", ".dmp", ".crash", ".txt", ".json.orig", ".copy"}
	for _, suf := range suffixes {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return strings.Contains(base, "crash") || strings.Contains(base, "heapdump")
}

// tksFilenameSensitive 判断文件名是否直接暴露敏感语义。
func tksFilenameSensitive(base string) bool {
	for _, kw := range []string{"token", "password", "passwd", "secret", "credential", "accesstoken", "refreshtoken"} {
		if strings.Contains(base, kw) {
			return true
		}
	}
	return false
}

// TKSEvaluate 评估一个存储位置。
func TKSEvaluate(site TKSSiteView, policy TKSPolicy) (safe bool, findings []TKSFinding) {
	base := tksPathBase(site.Path)

	if site.ContainsToken {
		findings = append(findings, TKSFinding{Reason: TKSReasonPlaintextToken, Detail: base})
		if policy.RequireOSProtection && !site.OSProtected {
			findings = append(findings, TKSFinding{Reason: TKSReasonNoOSProtection, Detail: base})
		}
		if policy.ForbidRefreshAlongside && site.HoldsAccess && site.HoldsRefresh {
			findings = append(findings, TKSFinding{Reason: TKSReasonRefreshAlongside, Detail: base})
		}
	}

	// 权限位：任何 group/other 位即过宽；含写位更严重
	if site.PermBits != 0 {
		groupOther := site.PermBits & 0o077
		if groupOther != 0 {
			findings = append(findings, TKSFinding{Reason: TKSReasonWorldReadable,
				Detail: tksPermString(site.PermBits)})
			if site.PermBits&0o022 != 0 {
				findings = append(findings, TKSFinding{Reason: TKSReasonWorldWritable})
			}
		}
		if site.PermBits&^policy.MaxAllowedPermBits != 0 {
			findings = append(findings, TKSFinding{Reason: TKSReasonInsecurePermissions,
				Detail: tksPermString(site.PermBits)})
		}
	}

	if site.InSharedOrTemp {
		findings = append(findings, TKSFinding{Reason: TKSReasonSharedOrTempLocation, Detail: base})
	}
	if site.IsBackupOrTemp || tksBackupLike(base) {
		findings = append(findings, TKSFinding{Reason: TKSReasonBackupCopyLeak, Detail: base})
	}
	if site.FilenameSensitive || tksFilenameSensitive(base) {
		findings = append(findings, TKSFinding{Reason: TKSReasonSensitiveInFilename, Detail: base})
	}
	return len(findings) == 0, findings
}

func tksPermString(bits uint32) string {
	const dig = "01234567"
	out := []byte{'0'}
	for shift := 6; shift >= 0; shift -= 3 {
		out = append(out, dig[(bits>>uint(shift))&0x7])
	}
	return string(out)
}
