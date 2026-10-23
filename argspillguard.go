package main

// argspillguard.go —— 命令行参数敏感信息泄露守卫。
//
// 背景：
//   启动器会 fork java / 外部下载器 / 解压工具。命令行参数在本机是"半公开"的：
// Windows 可被同账户其它进程通过进程快照/NtQuerySystemInformation 读到，Linux/macOS 可通过
//   /proc/<pid>/cmdline 与 ps 看到。把 access_token、密码、连接串、API key 放进参数，等于
//   泄露给同机任意普通进程；恶意 mod 或第三方整合包脚本即可顺手窃取。
//   正确做法是敏感值走 stdin / 环境变量（仍非完美但 cmdline 不可见）/ 受权临时文件 + UMFS 校验。
//   本模块扫描一个 argv 序列，识别"键=值"或紧跟值的敏感参数，给出结构化结论，纯字符实现。

import "strings"

const (
	APSReasonAccessToken   = "argv-access-token"
	APSReasonPassword      = "argv-password"
	APSReasonRefreshToken  = "argv-refresh-token"
	APSReasonClientSecret  = "argv-client-secret"
	APSReasonAPIKey        = "argv-api-key"
	APSReasonConnectionURL = "argv-credentials-in-url"
	APSReasonPrivateKey    = "argv-private-key-material"
	APSReasonSessionID     = "argv-session-id"
	APSReasonBearerInline  = "argv-bearer-inline"
)

// APSPolicy 决定哪些敏感类别需要拦截。
type APSPolicy struct {
	WarnSessionID bool // session 风险较低，默认只警告；true 时也判为不安全
}

// APSFinding 记录一处参数泄密。
type APSFinding struct {
	Reason  string
	Index   int
	ArgHint string // 仅保留键名/脱敏提示，不回显完整值
}

// DefaultAPSPolicy 返回默认策略。
func DefaultAPSPolicy() APSPolicy {
	return APSPolicy{WarnSessionID: false}
}

// apsSecretKeys 是"键=值"里需要拦截的键名（小写匹配，去前导横线）。
var apsSecretKeys = map[string]string{
	"access_token":  APSReasonAccessToken,
	"accesstoken":   APSReasonAccessToken,
	"token":         APSReasonAccessToken,
	"password":      APSReasonPassword,
	"passwd":        APSReasonPassword,
	"pwd":           APSReasonPassword,
	"refresh_token": APSReasonRefreshToken,
	"refreshtoken":  APSReasonRefreshToken,
	"client_secret": APSReasonClientSecret,
	"clientsecret":  APSReasonClientSecret,
	"api_key":       APSReasonAPIKey,
	"apikey":        APSReasonAPIKey,
	"x-api-key":     APSReasonAPIKey,
	"session_id":    APSReasonSessionID,
	"sessionid":     APSReasonSessionID,
	"sid":           APSReasonSessionID,
}

// apsFlagKeys 表示该开关的"下一个参数"是敏感值。
var apsFlagKeys = map[string]string{
	"--password":      APSReasonPassword,
	"-p":              APSReasonPassword,
	"--token":         APSReasonAccessToken,
	"--access-token":  APSReasonAccessToken,
	"--refresh-token": APSReasonRefreshToken,
	"--client-secret": APSReasonClientSecret,
	"--api-key":       APSReasonAPIKey,
}

func apsLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

func apsTrimDashes(s string) string {
	for len(s) > 0 && (s[0] == '-' || s[0] == '/') {
		s = s[1:]
	}
	return s
}

// apsURLCredentials 检测 URL 中内嵌的 user:pass@（连接串泄密）。
func apsURLCredentials(arg string) bool {
	at := strings.IndexByte(arg, '@')
	if at <= 0 {
		return false
	}
	head := arg[:at]
	// 找 scheme:// 之后的凭据段
	scheme := strings.Index(head, "://")
	if scheme >= 0 {
		head = head[scheme+3:]
	}
	if strings.IndexByte(head, '/') >= 0 {
		return false
	}
	return strings.IndexByte(head, ':') >= 0
}

// APSInspect 扫描 argv。返回安全与否及发现；建议把命中的值改为 stdin/env/受权文件。
func APSInspect(argv []string, policy APSPolicy) (safe bool, findings []APSFinding) {
	for idx := 0; idx < len(argv); idx++ {
		arg := argv[idx]
		low := apsLower(arg)

		// 1) 明文 bearer
		if strings.Contains(low, "bearer ") {
			findings = append(findings, APSFinding{Reason: APSReasonBearerInline, Index: idx})
		}
		// 2) PEM 私钥内容
		if strings.Contains(arg, "BEGIN") && strings.Contains(arg, "PRIVATE KEY") {
			findings = append(findings, APSFinding{Reason: APSReasonPrivateKey, Index: idx})
		}
		// 3) URL 内嵌凭据
		if apsURLCredentials(arg) {
			findings = append(findings, APSFinding{Reason: APSReasonConnectionURL, Index: idx})
		}

		// 4) 独立开关，下一个参数是值
		keyOnly := apsTrimDashes(low)
		if reason, ok := apsFlagKeys[keyOnly]; ok {
			findings = append(findings, APSFinding{Reason: reason, Index: idx, ArgHint: keyOnly})
			if idx+1 < len(argv) {
				idx++ // 跳过值参数，避免重复判定
			}
			continue
		}

		// 5) --key=value / -key=value / key=value
		if eq := strings.IndexByte(arg, '='); eq > 0 {
			k := apsTrimDashes(low[:eq])
			v := arg[eq+1:]
			if reason, ok := apsSecretKeys[k]; ok && strings.TrimSpace(v) != "" {
				findings = append(findings, APSFinding{Reason: reason, Index: idx, ArgHint: k})
			}
		}
	}

	if policy.WarnSessionID {
		return len(findings) == 0, findings
	}
	// session 类仅警告：从阻断结论中剔除，但仍在 findings 里保留提示
	blocking := make([]APSFinding, 0, len(findings))
	for _, f := range findings {
		if f.Reason != APSReasonSessionID {
			blocking = append(blocking, f)
		}
	}
	return len(blocking) == 0, findings
}
