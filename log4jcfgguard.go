package main

// log4jcfgguard.go —— Log4j/日志框架配置加载面守卫（配置文件 RCE 与遗留 JNDI 面）。
//
// 背景：
//   老版本 Minecraft 与大量 mod 仍随 Log4j2。除字符串消息里的 ${jndi:...}（由 jndiguard 覆盖）
//   之外，"配置从哪里加载"本身也是高危面：
//     - -Dlog4j.configurationFile=http://... 或 file:// 指向可控/远程配置，配置里可声明
//       JdbcAppender/JNDI lookup/脚本，加载即执行；
//     - -Dlog4j.configuration= 远程或相对路径，旧版 1.x 同样可加载恶意类；
//     - 配置文件本身普通用户可写（被植入 JNDI/ScriptManager）；
//     - 打开 lookup 开关 log4j2.formatMsgNoLookups=false（2.15 之前默认 true 即危险）；
//     - log4j 允许 ${jndi:}、${script:}、${jndiName:} 等 lookup（log4j2.enableJndi* 开关）。
//   本模块审查 JVM 系统属性与"日志配置文件视图"，纯字符串扫描，不使用正则。

import "strings"

const (
	L4CReasonRemoteConfig      = "log4j-remote-configuration-location"
	L4CReasonRelativeConfig    = "log4j-relative-or-bare-config-location"
	L4CReasonWritableConfig    = "log4j-config-file-world-writable"
	L4CReasonLookupsEnabled    = "log4j-message-lookups-enabled"
	L4CReasonJndiLookupEnabled = "log4j-jndi-lookup-enabled"
	L4CReasonScriptInConfig    = "log4j-script-or-jdbc-appender-in-config"
	L4CReasonJNDIInConfig      = "log4j-jndi-reference-in-config"
	L4CReasonUnsupportedScheme = "log4j-config-unsupported-scheme"
)

// L4CPolicy 设定日志配置要求。
type L4CPolicy struct {
	AllowNonFileScheme   bool
	AllowJndiLookups     bool
	AllowScriptAppenders bool
}

// L4CConfigView 描述日志配置来源与文件状态。
type L4CConfigView struct {
	ConfigLocation string // -Dlog4j.configurationFile / log4j.configuration 值
	ConfigWritable bool
	LookupsEnabled bool // formatMsgNoLookups=false 等价
	JndiEnabled    bool // -Dlog4j2.enableJndi* / -Dcom.sun.jndi... 放开
}

// L4CFinding 记录一处日志配置风险。
type L4CFinding struct {
	Reason string
	Detail string
}

// DefaultL4CPolicy 默认禁止远程配置/JNDI/脚本 appender。
func DefaultL4CPolicy() L4CPolicy {
	return L4CPolicy{}
}

// l4cScheme 提取 location 的 scheme（小写），无 scheme 返回空串。
func l4cScheme(loc string) string {
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

// l4cIsAbsoluteFileLocation 判断 file: 之后或裸路径是否为绝对路径。
func l4cIsAbsoluteFileLocation(loc string) bool {
	s := loc
	if strings.HasPrefix(s, "file:///") {
		s = s[len("file:///"):]
	} else if strings.HasPrefix(s, "file://") {
		s = s[len("file://"):]
	} else if strings.HasPrefix(s, "file:") {
		s = s[len("file:"):]
	}
	if len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		return true
	}
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\\`)
}

// L4CInspectProps 审查 JVM 系统属性中的日志配置项。
func L4CInspectProps(cfg L4CConfigView, policy L4CPolicy) (safe bool, findings []L4CFinding) {
	loc := strings.TrimSpace(cfg.ConfigLocation)
	if loc != "" {
		scheme := l4cScheme(loc)
		switch scheme {
		case "":
			// 裸文件名/相对路径，依赖工作目录，易被替换
			findings = append(findings, L4CFinding{Reason: L4CReasonRelativeConfig, Detail: loc})
		case "file":
			if !l4cIsAbsoluteFileLocation(loc) {
				findings = append(findings, L4CFinding{Reason: L4CReasonRelativeConfig, Detail: loc})
			}
			if cfg.ConfigWritable {
				findings = append(findings, L4CFinding{Reason: L4CReasonWritableConfig, Detail: loc})
			}
		case "http", "https", "ftp", "jar":
			if !policy.AllowNonFileScheme {
				findings = append(findings, L4CFinding{Reason: L4CReasonRemoteConfig, Detail: scheme})
			}
		default:
			findings = append(findings, L4CFinding{Reason: L4CReasonUnsupportedScheme, Detail: scheme})
		}
	}

	if cfg.LookupsEnabled {
		findings = append(findings, L4CFinding{Reason: L4CReasonLookupsEnabled})
	}
	if cfg.JndiEnabled && !policy.AllowJndiLookups {
		findings = append(findings, L4CFinding{Reason: L4CReasonJndiLookupEnabled})
	}
	return len(findings) == 0, findings
}

// L4CInspectConfigText 扫描一份日志配置文本中的危险元素。
func L4CInspectConfigText(configText string, policy L4CPolicy) (safe bool, findings []L4CFinding) {
	low := strings.ToLower(configText)

	jndiMarkers := []string{"${jndi:", "${jndiname:", "jndimanager", "ldap://", "rmi://", "dns://"}
	for _, m := range jndiMarkers {
		if strings.Contains(low, m) {
			findings = append(findings, L4CFinding{Reason: L4CReasonJNDIInConfig, Detail: m})
			break
		}
	}

	scriptMarkers := []string{
		"<script", "scriptmanager", "scriptappender", "scriptcondition",
		"<jdbc", "jdbcappender", "jdbcdatasourcesource",
		"javax.script", "javax.naming",
	}
	for _, m := range scriptMarkers {
		if strings.Contains(low, m) {
			reason := L4CReasonScriptInConfig
			findings = append(findings, L4CFinding{Reason: reason, Detail: m})
			break
		}
	}
	if policy.AllowScriptAppenders {
		// 策略允许脚本 appender 时，仅保留 JNDI 类结论
		filtered := make([]L4CFinding, 0, len(findings))
		for _, f := range findings {
			if f.Reason != L4CReasonScriptInConfig {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}
	return len(findings) == 0, findings
}
