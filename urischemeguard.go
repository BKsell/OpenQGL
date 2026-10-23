package main

// urischemeguard.go —— 启动器要抓取/加载/转交的 URL scheme 白名单守卫。
//
// 背景：
//   Go 侧会处理多种来源的 URL：Modrinth/CurseForge 文件地址、服务器图标、皮肤/披风、资源包、
//   整合包里的"主页链接"、版本日志链接等。URL 的 scheme 决定了"取数据"这一动作落在哪个协议栈：
//     - file:// 直接读本地文件，配合 SSRF/路径输入可越权读盘；
//     - jar:// / netjar: / gopher:// / ftp:// 走进意料之外的客户端实现或明文通道；
//     - data: 把任意字节内联进本该按"远程 URL"处理的字段，绕过主机钉扎与大小控制；
//     - javascript:/vbscript: 在被转交给可渲染组件时变 XSS；
//     - 自定义 scheme（minecraft://、steam://、ms-xxx:）可能唤起本地程序。
//   按"用途"分级允许：下载只允许 https；可点击外链允许 http/https 且需用户确认唤起（其它模块）；
//   任何取数场景都拒绝 file/data/脚本/危险内部 scheme。纯字符串 scheme 解析，不使用正则。

import "strings"

const (
	USMReasonSchemeMissing      = "uri-scheme-missing"
	USMReasonFileScheme         = "uri-file-scheme-on-remote-fetch"
	USMReasonDataScheme         = "uri-inline-data-scheme"
	USMReasonScriptScheme       = "uri-script-scheme"
	USMReasonInternalScheme     = "uri-internal-or-jar-scheme"
	USMReasonCustomLaunchScheme = "uri-custom-app-launch-scheme"
	USMReasonCleartextDownload  = "uri-plain-http-for-download"
	USMReasonSchemeNotAllowed   = "uri-scheme-not-in-allowlist"
)

// USMUsage 标明 URL 用途。
type USMUsage int

const (
	USMUsageDownload     USMUsage = iota // 真正下载字节落盘
	USMUsageFetchJSON                    // 拉取 JSON 元数据
	USMUsageDisplayImage                 // 显示图标/皮肤
	USMUsageExternalLink                 // 用户可点击的外链
)

// USMFinding 记录一处 scheme 风险。
type USMFinding struct {
	Reason string
	Detail string
}

// usmScheme 提取小写 scheme；无冒号返回空。
func usmScheme(raw string) string {
	s := strings.TrimSpace(raw)
	// 去前导空白/控制已在外部；找第一个 ':'，且 scheme 首字符必须是字母
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ':' {
			if i == 0 {
				return ""
			}
			cand := strings.ToLower(s[:i])
			first := cand[0]
			if !(first >= 'a' && first <= 'z') {
				return ""
			}
			for j := 1; j < len(cand); j++ {
				ch := cand[j]
				if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
					ch == '+' || ch == '-' || ch == '.') {
					return ""
				}
			}
			return cand
		}
		if c == '/' || c == '?' || c == '#' {
			break
		}
	}
	return ""
}

// USMCheck 按用途校验 URL scheme。
func USMCheck(rawURL string, usage USMUsage) (safe bool, scheme string, findings []USMFinding) {
	scheme = usmScheme(rawURL)
	add := func(reason, detail string) {
		findings = append(findings, USMFinding{Reason: reason, Detail: detail})
	}

	if scheme == "" {
		add(USMReasonSchemeMissing, "no-scheme")
		return false, scheme, findings
	}

	switch scheme {
	case "http":
		if usage == USMUsageDownload || usage == USMUsageFetchJSON || usage == USMUsageDisplayImage {
			add(USMReasonCleartextDownload, "http")
		}
		// 外链允许 http（交由用户确认流程），下载类上面已拒
	case "https":
		// 全部用途允许
	case "file":
		add(USMReasonFileScheme, "file")
	case "data":
		add(USMReasonDataScheme, "data")
	case "javascript", "vbscript", "livescript":
		add(USMReasonScriptScheme, scheme)
	case "jar", "netjar", "zip", "gopher", "ftp", "ftps", "ldap", "dict":
		add(USMReasonInternalScheme, scheme)
	default:
		// 已知的本地程序唤起 scheme
		launch := false
		for _, p := range []string{"minecraft", "ms-", "steam", "dial", "tel",
			"mailto", "magnet", "intent", "market", "slack", "tg"} {
			if scheme == p || strings.HasPrefix(scheme, p) {
				launch = true
				break
			}
		}
		if launch {
			add(USMReasonCustomLaunchScheme, scheme)
		} else {
			add(USMReasonSchemeNotAllowed, scheme)
		}
	}
	return len(findings) == 0, scheme, findings
}

// USMCheckMany 批量校验。
func USMCheckMany(urls []string, usage USMUsage) (safe bool, all []USMFinding) {
	for _, u := range urls {
		_, _, fs := USMCheck(u, usage)
		all = append(all, fs...)
	}
	return len(all) == 0, all
}
