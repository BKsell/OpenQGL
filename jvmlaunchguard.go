package main

// jvmlaunchguard.go —— Minecraft JVM 启动参数注入面守卫。
//
// 背景：
//   启动器最终要拼接一条 java 命令来跑游戏。JVM 参数来源复杂：内置默认、用户自定义、
//   版本清单里的 arguments.jvm、第三方整合包设置、内存自动检测。其中任何一段可控都可能
//   注入危险开关，使进程在"看起来只是启动游戏"时加载恶意代码或突破沙箱：
//     - -javaagent / -agentlib / -agentpath：在主类前执行任意字节码/本地库；
//     - -Xbootclasspath/a:：把恶意类塞进启动类路径，可覆盖 JDK 类；
//     - --add-opens / --add-exports / --enable-native-access：解除模块封装、放开 JNI；
//     - -cp / -classpath 里的通配符目录、相对路径与路径分隔符注入额外 jar；
//     - -Djava.library.path 指向攻击者目录加载本地库；
//     - 主类 / jar 被换成非预期值；环境变量 _JAVA_OPTIONS/JDK_JAVA_OPTIONS 旁路注入。
//   本模块对"最终 JVM 参数序列 + 关键环境变量"做策略审查，纯字符串扫描，不使用正则。

import (
	"strings"
)

const (
	JVLReasonJavaAgent          = "jvm-java-agent"
	JVLReasonAgentLib           = "jvm-agent-lib"
	JVLReasonBootClasspath      = "jvm-bootclasspath-override"
	JVLReasonAddOpensAll        = "jvm-add-opens-unnamed-all"
	JVLReasonEnableNativeAccess = "jvm-enable-native-access-all"
	JVLReasonLibraryPath        = "jvm-java-library-path"
	JVLReasonClasspathWildcard  = "jvm-classpath-wildcard-dir"
	JVLReasonClasspathRelative  = "jvm-classpath-relative-entry"
	JVLReasonClasspathSepInject = "jvm-classpath-separator-injection"
	JVLReasonUnexpectedMain     = "jvm-unexpected-main-class"
	JVLReasonEnvInjection       = "jvm-env-option-injection"
	JVLReasonDangerousProp      = "jvm-dangerous-system-property"
	JVLReasonDashJar            = "jvm-dash-jar-untrusted"
	JVLReasonEnableAssertions   = "jvm-remote-debug-open"
)

// JVLPolicy 控制允许哪些 JVM 能力。
type JVLPolicy struct {
	AllowAgents              bool
	AllowBootClasspath       bool
	AllowAddOpens            bool
	AllowNativeAccessAll     bool
	AllowLibraryPath         bool
	AllowClasspathWildcard   bool
	RequireAbsoluteClasspath bool
	AllowRemoteDebug         bool
	ExpectedMainClasses      map[string]bool // 允许的主类白名单（net.minecraft.client.main.Main 等）
	ExpectedJar              string          // 若走 -jar，允许的 jar（空表示禁止 -jar）
	DangerousProps           []string        // 不允许通过 -D 设置的属性前缀
}

// JVLFinding 记录一处危险 JVM 参数。
type JVLFinding struct {
	Reason string
	Token  string
	Detail string
}

// DefaultJVLPolicy 返回面向 Minecraft 客户端启动的保守策略。
func DefaultJVLPolicy() JVLPolicy {
	return JVLPolicy{
		AllowAgents:              false,
		AllowBootClasspath:       false,
		AllowAddOpens:            false,
		AllowNativeAccessAll:     false,
		AllowLibraryPath:         false,
		AllowClasspathWildcard:   false,
		RequireAbsoluteClasspath: true,
		AllowRemoteDebug:         false,
		ExpectedMainClasses: map[string]bool{
			"net.minecraft.client.main.Main": true,
			"io.github.legacyminecraft.Main": true,
		},
		DangerousProps: []string{
			"java.security.manager", "jdk.http.auth.tunneling.disabledSchemes",
			"com.sun.net.ssl.checkRevocation", "jdk.tls.client.protocols",
			"https.proxyHost", "socksProxyHost", "java.rmi.server.codebase",
		},
	}
}

func jvlLowerHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// jvlClasspathEntries 按平台分隔符切 classpath（Windows ';'，':' 通用）。
func jvlClasspathEntries(cp string) []string {
	var out []string
	cur := strings.Builder{}
	for i := 0; i < len(cp); i++ {
		c := cp[i]
		if c == ';' || c == ':' {
			// 注意 Windows 盘符 X: 中的 ':'，靠下一个字符是否为分隔符/结尾粗判
			if c == ':' && i+1 < len(cp) && cp[i+1] != ';' && cp[i+1] != '/' && cp[i+1] != '\\' {
				cur.WriteByte(c)
				continue
			}
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	out = append(out, cur.String())
	return out
}

func jvlIsAbsoluteEntry(e string) bool {
	if e == "" {
		return false
	}
	// Windows 盘符 X:\ 或 X:/，或 UNC \\，或 POSIX /
	if len(e) >= 3 && e[1] == ':' && (e[2] == '\\' || e[2] == '/') {
		return true
	}
	if strings.HasPrefix(e, `\\`) || strings.HasPrefix(e, "//") {
		return true
	}
	if e[0] == '/' {
		return true
	}
	return false
}

// JVLInspectEnv 检查旁路环境变量是否携带可注入的 JVM 选项。
func JVLInspectEnv(env map[string]string, findings []JVLFinding) []JVLFinding {
	for _, name := range []string{"_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"} {
		if v := strings.TrimSpace(env[name]); v != "" {
			findings = append(findings, JVLFinding{Reason: JVLReasonEnvInjection, Token: name, Detail: v})
		}
	}
	return findings
}

// JVLValidate 审查最终 JVM 参数序列。args 为传给 java 的全部参数（含 -cp/-D/主类）。
func JVLValidate(args []string, env map[string]string, policy JVLPolicy) (safe bool, findings []JVLFinding) {
	mainSeen := false
	nextIsClasspath := false
	nextIsJar := false

	for _, raw := range args {
		a := strings.TrimSpace(raw)
		if a == "" {
			continue
		}

		if nextIsClasspath {
			nextIsClasspath = false
			for _, e := range jvlClasspathEntries(a) {
				if strings.HasSuffix(e, "*") {
					if !policy.AllowClasspathWildcard {
						findings = append(findings, JVLFinding{Reason: JVLReasonClasspathWildcard, Token: e})
					}
					continue
				}
				if policy.RequireAbsoluteClasspath && !jvlIsAbsoluteEntry(e) {
					findings = append(findings, JVLFinding{Reason: JVLReasonClasspathRelative, Token: e})
				}
			}
			continue
		}
		if nextIsJar {
			nextIsJar = false
			mainSeen = true
			if policy.ExpectedJar == "" || a != policy.ExpectedJar {
				findings = append(findings, JVLFinding{Reason: JVLReasonDashJar, Token: a})
			}
			continue
		}

		switch {
		case a == "-cp" || a == "-classpath" || a == "--class-path":
			nextIsClasspath = true
			continue
		case a == "-jar":
			nextIsJar = true
			continue
		}

		switch {
		case jvlLowerHasPrefix(a, "-javaagent") || jvlLowerHasPrefix(a, "-agentlib") ||
			jvlLowerHasPrefix(a, "-agentpath"):
			reason := JVLReasonAgentLib
			if jvlLowerHasPrefix(a, "-javaagent") {
				reason = JVLReasonJavaAgent
			}
			if !policy.AllowAgents {
				findings = append(findings, JVLFinding{Reason: reason, Token: a})
			}
		case jvlLowerHasPrefix(a, "-xbootclasspath"):
			if !policy.AllowBootClasspath {
				findings = append(findings, JVLFinding{Reason: JVLReasonBootClasspath, Token: a})
			}
		case strings.HasPrefix(a, "--add-opens") || strings.HasPrefix(a, "--add-exports"):
			if !policy.AllowAddOpens {
				detail := ""
				if strings.Contains(a, "=ALL-UNNAMED") {
					detail = "ALL-UNNAMED"
				}
				findings = append(findings, JVLFinding{Reason: JVLReasonAddOpensAll, Token: a, Detail: detail})
			}
		case strings.HasPrefix(a, "--enable-native-access"):
			if !policy.AllowNativeAccessAll && strings.Contains(a, "=ALL-UNNAMED") {
				findings = append(findings, JVLFinding{Reason: JVLReasonEnableNativeAccess, Token: a})
			}
		case strings.HasPrefix(a, "-Djava.library.path") || strings.HasPrefix(a, "-Dsun.boot.library.path"):
			if !policy.AllowLibraryPath {
				findings = append(findings, JVLFinding{Reason: JVLReasonLibraryPath, Token: a})
			}
		case strings.HasPrefix(a, "-agentlib:jdwp") || strings.Contains(a, "address=*:"):
			if !policy.AllowRemoteDebug {
				findings = append(findings, JVLFinding{Reason: JVLReasonEnableAssertions, Token: a})
			}
		case strings.HasPrefix(a, "-D"):
			kv := a[2:]
			for _, p := range policy.DangerousProps {
				if kv == p || strings.HasPrefix(kv, p+"=") {
					findings = append(findings, JVLFinding{Reason: JVLReasonDangerousProp, Token: a})
					break
				}
			}
		case strings.HasPrefix(a, "-"):
			// 其它 JVM 开关，安全（如 -Xmx）
		default:
			// 第一个非开关 token 即主类
			if !mainSeen {
				mainSeen = true
				if len(policy.ExpectedMainClasses) > 0 && !policy.ExpectedMainClasses[a] {
					findings = append(findings, JVLFinding{Reason: JVLReasonUnexpectedMain, Token: a})
				}
			}
		}
	}
	findings = JVLInspectEnv(env, findings)
	return len(findings) == 0, findings
}
