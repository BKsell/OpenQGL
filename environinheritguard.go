package main

// environinheritguard.go —— spawn JVM/外部工具时继承的环境变量注入守卫。
//
// 背景：
//   JVM 会自动读取若干环境变量并据此追加参数/agent，而这些变量可被用户会话、其它程序、或解压的
//   存档目录预置，属于"不靠命令行也能注入 JVM"的经典通道：
//     - JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS / _JAVA_OPTIONS：全局 JVM 参数（可塞 -javaagent）；
//     - CLASSPATH：污染类搜索路径，让恶意类优先于正版；
//     - JAVA_HOME / PATH：重定向到被替换的 java；
//     - JPDA_*、JAVA_TOOL_OPTIONS 里的 -agentlib；
//     - 任意变量值里的命令替换痕迹与路径指向实例目录之外。
//   本模块审计"准备交给子进程的环境集合"，给出应清除/显式重写的变量；纯字符串判定，不用正则。

const (
	EIReasonJVMOptionsOverride         = "env-jvm-tool-options-inherited"
	EIReasonClassPathOverride          = "env-classpath-inherited"
	EIReasonJavaHomeOverride           = "env-java-home-or-path-inherited-unverified"
	EIReasonAgentLibInValue            = "env-value-injects-agentlib-or-javaagent"
	EIReasonSensitiveSecretPassthrough = "env-process-inherits-known-secret-variable"
)

// EISensitiveEnv 是 JVM 会自动消费、必须显式管控（清除或由启动器重写）的变量（大写）。
var EISensitiveEnv = map[string]bool{
	"JAVA_TOOL_OPTIONS": true,
	"JDK_JAVA_OPTIONS":  true,
	"_JAVA_OPTIONS":     true,
}

// EINeverBareInherit 是不允许未经校验直接继承的路径类变量。
var EINeverBareInherit = map[string]bool{
	"CLASSPATH": true,
	"JAVA_HOME": true,
	"PATH":      true,
}

// EISecretLike 是按命名识别的密钥类变量（不应进子进程，除非显式需要）。
var EISecretLike = map[string]bool{
	"AWS_SECRET_ACCESS_KEY": true,
	"AWS_ACCESS_KEY_ID":     true,
	"GITHUB_TOKEN":          true,
	"MOJANG_TOKEN":          true,
}

// EIFinding 记录一处环境继承问题。
type EIFinding struct {
	Reason string
	Name   string
}

// EIAuditEnv 审计继承给子进程的环境变量。
// trustedJavaHome 为启动器自己选定并校验过的 JAVA_HOME（小写比较）；空表示未配置可信值。
func EIAuditEnv(env map[string]string, trustedJavaHome string) (safe bool, findings []EIFinding) {
	for name, value := range env {
		up := eiUpper(name)
		if EISensitiveEnv[up] {
			findings = append(findings, EIFinding{Reason: EIReasonJVMOptionsOverride, Name: up})
		}
		if EINeverBareInherit[up] {
			switch up {
			case "CLASSPATH":
				findings = append(findings, EIFinding{Reason: EIReasonClassPathOverride, Name: up})
			case "JAVA_HOME":
				if trustedJavaHome == "" || eiLower(value) != eiLower(trustedJavaHome) {
					findings = append(findings, EIFinding{Reason: EIReasonJavaHomeOverride, Name: up})
				}
			default: // PATH
				findings = append(findings, EIFinding{Reason: EIReasonJavaHomeOverride, Name: up})
			}
		}
		if EISecretLike[up] {
			findings = append(findings, EIFinding{Reason: EIReasonSensitiveSecretPassthrough, Name: up})
		}
		if eiContainsAgent(value) {
			findings = append(findings, EIFinding{Reason: EIReasonAgentLibInValue, Name: up})
		}
	}
	return len(findings) == 0, findings
}

// EISanitize 返回删除敏感/危险变量后的干净环境（启动器再按需显式加入白名单变量）。
func EISanitize(env map[string]string) map[string]string {
	out := map[string]string{}
	for name, value := range env {
		up := eiUpper(name)
		if EISensitiveEnv[up] || EINeverBareInherit[up] || EISecretLike[up] ||
			eiContainsAgent(value) {
			continue
		}
		out[name] = value
	}
	return out
}

func eiContainsAgent(v string) bool {
	low := eiLower(v)
	return eiContains(low, "-javaagent") || eiContains(low, "-agentlib") ||
		eiContains(low, "-agentpath")
}

func eiContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func eiUpper(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 0x20
		}
	}
	return string(b)
}

func eiLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

// EIHasReason 判定结果含某类问题。
func EIHasReason(findings []EIFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
