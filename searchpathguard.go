package main

// searchpathguard.go —— 可执行文件搜索路径（PATH）劫持检测。
//
// 背景：
//   启动器需要查找 java/javaw 以及外部工具。若直接按未净化的 PATH 用 exec.LookPath 风格查找，可能：
//     - PATH 含空分量或 "."，使当前工作目录（可被恶意存档/下载目录写入）优先于系统目录；
//     - PATH 中排在系统目录前的、普通用户可写目录里被植入同名 java.exe；
//     - 未限定扩展名就接受 .bat/.cmd（可注入任意命令）而不是可执行二进制；
//     - 找到的可执行文件所在目录对非管理员可写（DLL/EXE 同目录劫持）。
//   本模块对"PATH 分量序列 + 候选命中"做判定，writableDirs 由调用方按文件系统 ACL 提供，
//   纯字符串建模，不直接访问文件系统，不使用正则。

const (
	SPReasonEmptyPathComponent = "searchpath-empty-or-cwd-component-before-system"
	SPReasonWritableDirFirst   = "searchpath-user-writable-directory-precedes-system"
	SPReasonUnsafeExtension    = "searchpath-resolved-executable-is-script-not-binary"
	SPReasonCandidateWritable  = "searchpath-resolved-binary-location-user-writable"
	SPReasonOutsideSystemRoot  = "searchpath-java-resolved-outside-trusted-roots"
)

// SPFinding 记录一处搜索路径风险。
type SPFinding struct {
	Reason string
	Detail string
}

// SPSystemToken 标记可信系统目录的匹配分量（如 C:\Windows、Program Files、JDK 安装目录）。
// SPConfig 描述一次查找的环境。
type SPConfig struct {
	// PathEntries 为按顺序的 PATH 分量（已按 OS 分隔符拆开）。
	PathEntries []string
	// WritableEntries 为普通用户可写的 PATH 分量集合（键为分量小写形式）。
	WritableEntries map[string]bool
	// TrustedRoots 为允许解析 java 的可信根目录小写集合。
	TrustedRoots map[string]bool
	// AllowScripts 为 true 时允许 .bat/.cmd（默认应 false）。
	AllowScripts bool
}

// SPAuditPath 审计 PATH 序列本身（不含具体命中）。
func SPAuditPath(cfg SPConfig) (safe bool, findings []SPFinding) {
	seenSystem := false
	for idx, e := range cfg.PathEntries {
		key := spLower(e)
		if key == "" || key == "." {
			if !seenSystem {
				findings = append(findings, SPFinding{Reason: SPReasonEmptyPathComponent,
					Detail: spItoa(idx)})
			}
			continue
		}
		if cfg.WritableEntries[key] {
			if !seenSystem {
				findings = append(findings, SPFinding{Reason: SPReasonWritableDirFirst,
					Detail: e})
			}
		}
		if cfg.TrustedRoots[key] {
			seenSystem = true
		}
	}
	return len(findings) == 0, findings
}

// SPResolve 审计最终命中的可执行文件。
// resolvedDir 为命中文件所在目录；ext 为扩展名（.exe/.bat/...）。
func SPResolve(cfg SPConfig, resolvedDir, ext string) (safe bool, findings []SPFinding) {
	e := spLower(ext)
	if e != ".exe" && e != "" {
		if !cfg.AllowScripts {
			findings = append(findings, SPFinding{Reason: SPReasonUnsafeExtension,
				Detail: ext})
		}
	}
	dirKey := spLower(resolvedDir)
	if cfg.WritableEntries[dirKey] {
		findings = append(findings, SPFinding{Reason: SPReasonCandidateWritable,
			Detail: resolvedDir})
	}
	trusted := false
	for root := range cfg.TrustedRoots {
		if spHasPrefix(dirKey, root) {
			trusted = true
			break
		}
	}
	if !trusted && len(cfg.TrustedRoots) > 0 {
		findings = append(findings, SPFinding{Reason: SPReasonOutsideSystemRoot,
			Detail: resolvedDir})
	}
	return len(findings) == 0, findings
}

func spLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func spHasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}

func spItoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// SPHasReason 判定结果含某类问题。
func SPHasReason(findings []SPFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
