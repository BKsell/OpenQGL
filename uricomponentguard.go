package main

// uricomponentguard.go —— 出向 URI 各组件的长度、端口与百分号编码合法性守卫。
//
// 背景：
//   启动器拼接下载/登录 URL，组件级缺陷会引发缓冲区问题、绕过或歧义解析：
//     - 超长 URL / host / query，在下游 C 组件或日志里被截断；
//     - 端口越界（0、>65535）、负端口、多端口（host:1:2）；
//     - 空 host（http:///path）、scheme 用数字或过短；
//     - 畸形 %XX（%zz、%2、结尾%）导致不同解析器理解不一致；
//     - userinfo 内嵌凭据（http://user:pass@host）；
//   纯字符解析，不使用正则。

const (
	UCReasonURLOverlong   = "uri-total-length-exceeds-limit"
	UCReasonHostOverlong  = "uri-host-label-or-name-too-long"
	UCReasonPortInvalid   = "uri-port-out-of-range-or-malformed"
	UCReasonEmptyHost     = "uri-has-empty-host"
	UCReasonBadPercent    = "uri-percent-encoding-malformed"
	UCReasonUserInfo      = "uri-contains-userinfo-credentials"
	UCReasonMultiplePorts = "uri-host-contains-multiple-port-colons-outside-ipv6"
)

const (
	UCMaxURLLen  = 8192
	UCMaxHostLen = 253
	UCMaxLabel   = 63
)

// UCFinding 记录一处 URI 组件问题。
type UCFinding struct {
	Reason string
	Detail string
}

// UCAuditURI 审计一个已拆出 scheme/host/port/query 的 URI（调用方提供组件，避免这里重复做完整 URL 解析）。
type UCAuditInput struct {
	FullURL     string
	Scheme      string
	Host        string // 不含端口；IPv6 不含方括号
	Port        string // 空表示无端口
	HasUserInfo bool
}

// UCAudit 审计 URI 组件。
func UCAudit(in UCAuditInput) (safe bool, findings []UCFinding) {
	if len(in.FullURL) > UCMaxURLLen {
		findings = append(findings, UCFinding{Reason: UCReasonURLOverlong,
			Detail: ucItoa(len(in.FullURL))})
	}
	if in.HasUserInfo {
		findings = append(findings, UCFinding{Reason: UCReasonUserInfo})
	}
	if in.Host == "" {
		findings = append(findings, UCFinding{Reason: UCReasonEmptyHost})
	}
	// host 长度与标签长度（IPv6 跳过标签规则）
	if in.Host != "" && !ucIsV6(in.Host) {
		if len(in.Host) > UCMaxHostLen {
			findings = append(findings, UCFinding{Reason: UCReasonHostOverlong})
		}
		for _, label := range ucSplitDot(in.Host) {
			if len(label) > UCMaxLabel {
				findings = append(findings, UCFinding{Reason: UCReasonHostOverlong,
					Detail: "label>" + ucItoa(UCMaxLabel)})
			}
		}
	}
	if in.Port != "" {
		if !ucValidPort(in.Port) {
			findings = append(findings, UCFinding{Reason: UCReasonPortInvalid,
				Detail: in.Port})
		}
	}
	if !ucIsV6(in.Host) && ucColonCount(in.Host) > 0 {
		findings = append(findings, UCFinding{Reason: UCReasonMultiplePorts})
	}
	for _, bad := range ucBadPercentRuns(in.FullURL) {
		findings = append(findings, UCFinding{Reason: UCReasonBadPercent, Detail: bad})
	}
	return len(findings) == 0, findings
}

func ucValidPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
		n = n*10 + int(p[i]-'0')
		if n > 65535 {
			return false
		}
	}
	return n > 0
}

// ucBadPercentRuns 返回所有畸形百分号编码的位置串。
func ucBadPercentRuns(s string) []string {
	var bad []string
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) || !ucIsHex(s[i+1]) || !ucIsHex(s[i+2]) {
				bad = append(bad, ucItoa(i))
				// 跳到末尾可用范围
				if i+2 >= len(s) {
					break
				}
			}
		}
	}
	return bad
}

func ucIsHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func ucIsV6(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			return true
		}
	}
	return false
}

func ucColonCount(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			n++
		}
	}
	return n
}

func ucSplitDot(s string) []string {
	var out []string
	cur := ""
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, cur)
			cur = ""
			if i == len(s) {
				break
			}
			continue
		}
		cur += string(s[i])
	}
	return out
}

func ucItoa(i int) string {
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

// UCHasReason 判定结果含某类问题。
func UCHasReason(findings []UCFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
