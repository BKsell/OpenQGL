package main

// secpolicyguard.go —— Java SecurityManager / policy 文件授权面守卫。
//
// 背景：
//   一些老 mod/库依赖 SecurityManager，并通过 -Djava.security.manager、-Djava.security.policy、
//   -Djava.security.properties 改变安全策略。错误配置等于把沙箱拆了：
//     - policy 里 grant { permission java.security.AllPermission; }，对所有 codeBase 放权；
//     - policy 文件来自远程(http)、相对路径或普通用户可写；
//     - -Djava.security.properties==URL 用 '==' 完全覆盖 JDK 默认策略（单 '=' 是追加合并）；
//     - 显式关闭 SecurityManager 相关保护，或把 policy.url.n 指到可控位置；
//     - 放开 RuntimePermission(createClassLoader/exitVM/loadLibrary.*)、
//       ReflectPermission suppressAccessChecks 等高危细粒度权限。
//   本模块审查 JVM 属性与 policy 文本，纯字符串扫描，不使用正则。

import "strings"

const (
	SCPReasonAllPermission           = "secpolicy-all-permission-grant"
	SCPReasonRemotePolicy            = "secpolicy-remote-policy-location"
	SCPReasonRelativePolicy          = "secpolicy-relative-policy-location"
	SCPReasonWritablePolicy          = "secpolicy-policy-file-writable"
	SCPReasonPolicyOverrides         = "secpolicy-properties-full-override"
	SCPReasonDangerousPermission     = "secpolicy-dangerous-runtime-permission"
	SCPReasonPolicyURLReplaced       = "secpolicy-policy-url-replaced"
	SCPReasonPolicyUnsupportedScheme = "secpolicy-policy-unsupported-scheme"
)

// SCPPolicy 设定策略审查要求。
type SCPPolicy struct {
	AllowRemotePolicy     bool
	AllowAllPermission    bool
	AllowDangerousRuntime bool
}

// SCPPropsView 描述相关 JVM 属性。
type SCPPropsView struct {
	SecurityManagerSet bool
	PolicyLocation     string // -Djava.security.policy
	PropertiesLocation string // -Djava.security.properties
	PropertiesOverride bool   // 是否使用 '==' 完全覆盖
	PolicyURLReplaced  bool   // policy.url.n 是否被替换
	PolicyWritable     bool
}

// SCPFinding 记录一处安全策略风险。
type SCPFinding struct {
	Reason string
	Detail string
}

// DefaultSCPPolicy 默认全部收紧。
func DefaultSCPPolicy() SCPPolicy {
	return SCPPolicy{}
}

// scpScheme 提取 location scheme。
func scpScheme(loc string) string {
	for i := 0; i < len(loc); i++ {
		c := loc[i]
		if c == ':' {
			if i > 0 {
				return strings.ToLower(loc[:i])
			}
			return ""
		}
		if c == '/' || c == '\\' {
			return ""
		}
	}
	return ""
}

func scpAbsolute(loc string) bool {
	s := loc
	for _, p := range []string{"file:///", "file://", "file:"} {
		if strings.HasPrefix(s, p) {
			s = s[len(p):]
			break
		}
	}
	if len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		return true
	}
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\\`)
}

// SCPInspectProps 审查安全策略相关 JVM 属性。
func SCPInspectProps(view SCPPropsView, policy SCPPolicy) (safe bool, findings []SCPFinding) {
	if loc := strings.TrimSpace(view.PolicyLocation); loc != "" {
		scheme := scpScheme(loc)
		switch scheme {
		case "":
			findings = append(findings, SCPFinding{Reason: SCPReasonRelativePolicy, Detail: loc})
		case "file":
			if !scpAbsolute(loc) {
				findings = append(findings, SCPFinding{Reason: SCPReasonRelativePolicy, Detail: loc})
			}
			if view.PolicyWritable {
				findings = append(findings, SCPFinding{Reason: SCPReasonWritablePolicy, Detail: loc})
			}
		case "http", "https", "ftp", "jar":
			if !policy.AllowRemotePolicy {
				findings = append(findings, SCPFinding{Reason: SCPReasonRemotePolicy, Detail: scheme})
			}
		default:
			findings = append(findings, SCPFinding{Reason: SCPReasonPolicyUnsupportedScheme, Detail: scheme})
		}
	}

	if loc := strings.TrimSpace(view.PropertiesLocation); loc != "" {
		if view.PropertiesOverride {
			findings = append(findings, SCPFinding{Reason: SCPReasonPolicyOverrides, Detail: loc})
		}
		scheme := scpScheme(loc)
		if scheme == "http" || scheme == "https" || scheme == "ftp" || scheme == "jar" {
			if !policy.AllowRemotePolicy {
				findings = append(findings, SCPFinding{Reason: SCPReasonRemotePolicy, Detail: "properties:" + scheme})
			}
		}
	}
	if view.PolicyURLReplaced {
		findings = append(findings, SCPFinding{Reason: SCPReasonPolicyURLReplaced})
	}
	return len(findings) == 0, findings
}

// scpDangerousPermissions 是 policy 文本里需要报警的高危权限（小写子串匹配）。
var scpDangerousPermissions = []string{
	"java.security.allpermission",
	"java.lang.runtimepermission",
	"createclassloader",
	"exitvm",
	"loadlibrary.",
	"setsecuritymanager",
	"createaccesscontrolcontext",
	"java.lang.reflect.reflectpermission",
	"suppressaccesschecks",
	"java.io.filepermission",
	"java.net.socketpermission",
	"accept,connect,listen,resolve",
	"javax.script.scriptengine",
	"java.util.logging.loggingpermission",
	"control",
}

// SCPInspectPolicyText 扫描 .policy 文件文本中的危险授权。
func SCPInspectPolicyText(text string, policy SCPPolicy) (safe bool, findings []SCPFinding) {
	low := strings.ToLower(text)

	if !policy.AllowAllPermission && strings.Contains(low, "java.security.allpermission") {
		findings = append(findings, SCPFinding{Reason: SCPReasonAllPermission})
	}

	if !policy.AllowDangerousRuntime {
		hit := ""
		for _, p := range scpDangerousPermissions {
			if p == "java.security.allpermission" {
				continue
			}
			if strings.Contains(low, p) {
				hit = p
				break
			}
		}
		if hit != "" {
			findings = append(findings, SCPFinding{Reason: SCPReasonDangerousPermission, Detail: hit})
		}
	}

	// grant 未限定 codeBase/signedBy（对所有来源放权）
	if strings.Contains(low, "grant") && strings.Contains(low, "permission") {
		if scpGrantGlobal(low) {
			if !policy.AllowDangerousRuntime {
				findings = append(findings, SCPFinding{Reason: SCPReasonDangerousPermission, Detail: "global-grant"})
			}
		}
	}
	return len(findings) == 0, findings
}

// scpGrantGlobal 粗判是否存在 "grant {" 形式的无来源限制授权。
func scpGrantGlobal(low string) bool {
	search := 0
	for {
		idx := strings.Index(low[search:], "grant")
		if idx < 0 {
			return false
		}
		abs := search + idx + len("grant")
		// 跳过空白，找下一个非空白字符
		j := abs
		for j < len(low) && (low[j] == ' ' || low[j] == '\t' || low[j] == '\n' || low[j] == '\r') {
			j++
		}
		if j < len(low) && low[j] == '{' {
			// 该 grant 块内是否含 permission
			end := strings.IndexByte(low[j:], '}')
			block := ""
			if end >= 0 {
				block = low[j : j+end]
			} else {
				block = low[j:]
			}
			if strings.Contains(block, "permission") {
				return true
			}
		}
		search = abs
	}
}
