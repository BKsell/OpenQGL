package main

// modclasspathguard.go —— 第三方 mod/jar 的清单类路径与主类注入守卫。
//
// 背景：
//   启动器加载 Fabric/Forge mod、把多个 jar 拼进 -cp。jar 的 META-INF/MANIFEST.MF 可声明：
//     - Class-Path: ../../../../xxx.jar —— 相对类路径可指向实例目录之外（配合下载目录里的文件）；
//     - Main-Class / Launcher-Agent-Class 被老的 -jar 或预加载机制采用，植入恶意启动类；
//     - Premain-Class/Agent-Class（javaagent）可在启动期改写字节码；
//     - 绝对路径（C:\、\\UNC、/etc）或带 URL scheme 的 Class-Path 项；
//   本模块对已解析出的 manifest 关键属性值做判定，不解析 jar、不使用正则。

const (
	MCReasonClassPathTraversal = "manifest-classpath-entry-escapes-instance-dir"
	MCReasonClassPathAbsolute  = "manifest-classpath-entry-absolute-or-unc"
	MCReasonClassPathScheme    = "manifest-classpath-entry-contains-url-scheme"
	MCReasonAgentClass         = "manifest-declares-javaagent-premain-agent-class"
	MCReasonUnexpectedMain     = "manifest-declares-main-class-for-library-jar"
	MCReasonEntryCRLF          = "manifest-attribute-value-contains-crlf"
)

// MCFinding 记录一处 manifest 风险。
type MCFinding struct {
	Reason string
	Detail string
}

// MCManifest 是从 jar 清单中提取的关键字段（调用方解析后喂入）。
type MCManifest struct {
	ClassPathEntries   []string
	MainClass          string
	PremainClass       string
	AgentClass         string
	LauncherAgentClass string
	// IsExecutableJar 表示该 jar 本身就是要以 -jar 运行的主程序（允许 Main-Class）；
	// 普通 mod/库 jar 应为 false。
	IsExecutableJar bool
}

// MCAuditManifest 审计清单。
func MCAuditManifest(m MCManifest) (safe bool, findings []MCFinding) {
	for _, e := range m.ClassPathEntries {
		if mcContainsCRLF(e) {
			findings = append(findings, MCFinding{Reason: MCReasonEntryCRLF, Detail: e})
		}
		if mcIsAbsoluteOrUNC(e) {
			findings = append(findings, MCFinding{Reason: MCReasonClassPathAbsolute, Detail: e})
		}
		if mcHasScheme(e) {
			findings = append(findings, MCFinding{Reason: MCReasonClassPathScheme, Detail: e})
		}
		if mcEscapesInstance(e) {
			findings = append(findings, MCFinding{Reason: MCReasonClassPathTraversal, Detail: e})
		}
	}

	if m.PremainClass != "" {
		findings = append(findings, MCFinding{Reason: MCReasonAgentClass, Detail: m.PremainClass})
	}
	if m.AgentClass != "" {
		findings = append(findings, MCFinding{Reason: MCReasonAgentClass, Detail: m.AgentClass})
	}
	if m.LauncherAgentClass != "" {
		findings = append(findings, MCFinding{Reason: MCReasonAgentClass, Detail: m.LauncherAgentClass})
	}
	if m.MainClass != "" && !m.IsExecutableJar {
		findings = append(findings, MCFinding{Reason: MCReasonUnexpectedMain, Detail: m.MainClass})
	}
	return len(findings) == 0, findings
}

func mcEscapesInstance(entry string) bool {
	// 规范化反斜杠为正斜杠后做分量计数：出现 ".." 即视为可逃逸
	s := entry
	conv := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			conv = append(conv, '/')
		} else {
			conv = append(conv, s[i])
		}
	}
	norm := string(conv)
	// 按 / 拆分量，任意分量为 ".." 即逃逸
	start := 0
	for i := 0; i <= len(norm); i++ {
		if i == len(norm) || norm[i] == '/' {
			comp := norm[start:i]
			if comp == ".." {
				return true
			}
			start = i + 1
		}
	}
	return false
}

func mcIsAbsoluteOrUNC(e string) bool {
	if len(e) >= 2 && e[1] == ':' {
		c := e[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	if len(e) >= 2 && e[0] == '\\' && e[1] == '\\' {
		return true
	}
	if len(e) >= 1 && e[0] == '/' {
		return true
	}
	return false
}

func mcHasScheme(e string) bool {
	// 形如 xxx:// （至少一个字母开头，冒号双斜杠）
	for i := 0; i+2 < len(e); i++ {
		if e[i] == ':' && e[i+1] == '/' && e[i+2] == '/' && i > 0 {
			return true
		}
	}
	return false
}

func mcContainsCRLF(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return true
		}
	}
	return false
}

// MCHasReason 判定结果含某类问题。
func MCHasReason(findings []MCFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
