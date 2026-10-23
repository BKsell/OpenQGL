package main

// deeplinkguard.go —— 自定义 scheme 深链（mylauncher:// 等）参数与动作校验。
//
// 背景：
//   桌面启动器常注册自定义协议，浏览器/网页可用 <a href="mylauncher://action?..."> 唤起本地程序。
//   深链参数进入高权限本地上下文，是网页跨越沙箱打本机的直接通道：
//     - action 不在白名单（任意调用内部 IPC，如 deeplink://run?cmd=...）；
//     - 参数里的相对路径/绝对路径/UNC（导入实例时路径穿越、读取任意文件）；
//     - 深链携带的 next/redirect URL 造成开放重定向或把令牌带到第三方；
//     - 参数内嵌换行/控制字符（注入到后续命令行或配置）；
//     - 用 file/data/javascript 等危险 scheme 作为内部跳转目标；
//     - 超长深链、嵌套 URL、参数中的令牌被写进日志。
//   本模块纯字符串解析（手写 query 解析，不用 net/url、不用正则），动作白名单 + 参数净化。

const (
	DLKReasonUnknownAction    = "deeplink-unknown-action"
	DLKReasonMissingAction    = "deeplink-missing-action"
	DLKReasonPathTraversal    = "deeplink-param-path-traversal"
	DLKReasonUNCTarget        = "deeplink-param-unc-path"
	DLKReasonDangerousScheme  = "deeplink-target-dangerous-scheme"
	DLKReasonOpenRedirect     = "deeplink-open-redirect-host"
	DLKReasonControlChar      = "deeplink-param-control-char"
	DLKReasonTooLong          = "deeplink-too-long"
	DLKReasonSensitiveInParam = "deeplink-sensitive-token-in-param"
)

const DLKMaxURLLen = 2048

// DLKAllowedAction 描述一个允许的深链动作及其可带的参数。
type DLKAllowedAction struct {
	Name        string
	Params      map[string]bool // 允许出现的参数名集合
	IsURLParam  map[string]bool // 其中需要按 URL 校验的参数
	IsPathParam map[string]bool // 其中需要按路径校验的参数
}

// DLKConfig 深链接策略。
type DLKConfig struct {
	Scheme       string
	AllowedHosts map[string]bool // 内部跳转/redirect 允许的主机
	Actions      map[string]DLKAllowedAction
}

// DLKFinding 记录一处深链风险。
type DLKFinding struct {
	Reason string
	Param  string
	Value  string
}

// DLKResult 解析/校验结果。
type DLKResult struct {
	Safe     bool
	Action   string
	Params   map[string]string
	Findings []DLKFinding
}

var dlkDangerousSchemes = map[string]bool{
	"file": true, "data": true, "javascript": true, "vbscript": true,
	"jar": true, "netdoc": true, "ms-msdt": true, "ms-officecmd": true,
}

var dlkSensitiveNames = map[string]bool{
	"token": true, "access_token": true, "password": true, "secret": true,
	"code": true, "session": true, "authorization": true,
}

// DLKParseAudit 解析并审计一个深链 URL。
func DLKParseAudit(rawURL string, cfg DLKConfig) DLKResult {
	var findings []DLKFinding
	res := DLKResult{Params: map[string]string{}}

	if len(rawURL) > DLKMaxURLLen {
		findings = append(findings, DLKFinding{Reason: DLKReasonTooLong})
	}

	schemeTail, ok := dlkStripScheme(rawURL, cfg.Scheme)
	if !ok {
		// 非本启动器协议：交由调用方决定，这里不解析；返回不安全由调用方拒绝
		return DLKResult{Safe: false, Findings: []DLKFinding{{Reason: DLKReasonUnknownAction}}}
	}

	// scheme://action/path?query 或 scheme:action?query
	rest := schemeTail
	// 去掉 //
	if len(rest) >= 2 && rest[0:2] == "//" {
		rest = rest[2:]
	}
	// action 到 / 或 ? 为止
	action := rest
	query := ""
	for i := 0; i < len(rest); i++ {
		if rest[i] == '?' {
			action = rest[:i]
			query = rest[i+1:]
			break
		}
		if rest[i] == '/' || rest[i] == '\\' {
			action = rest[:i]
		}
	}
	res.Action = action
	if action == "" {
		findings = append(findings, DLKFinding{Reason: DLKReasonMissingAction})
	}

	rule, known := cfg.Actions[action]
	if !known {
		findings = append(findings, DLKFinding{Reason: DLKReasonUnknownAction, Value: action})
	}

	params := dlkParseQuery(query)
	for k, v := range params {
		if dlkSensitiveNames[dlkLower(k)] {
			findings = append(findings, DLKFinding{Reason: DLKReasonSensitiveInParam, Param: k})
		}
		if dlkHasControl(v) {
			findings = append(findings, DLKFinding{Reason: DLKReasonControlChar, Param: k})
		}
		if known {
			if !rule.Params[k] {
				// 未声明参数：保守记为可疑（可能利用未审计参数）
				findings = append(findings, DLKFinding{Reason: DLKReasonUnknownAction, Param: k})
			}
			if rule.IsPathParam[k] && dlkPathEscapes(v) {
				findings = append(findings, DLKFinding{Reason: DLKReasonPathTraversal, Param: k, Value: v})
			}
			if rule.IsPathParam[k] && dlkIsUNC(v) {
				findings = append(findings, DLKFinding{Reason: DLKReasonUNCTarget, Param: k, Value: v})
			}
			if rule.IsURLParam[k] {
				if s := dlkURLScheme(v); s != "" && dlkDangerousSchemes[s] {
					findings = append(findings, DLKFinding{Reason: DLKReasonDangerousScheme, Param: k, Value: s})
				}
				if host := dlkURLHost(v); host != "" && !cfg.AllowedHosts[host] {
					findings = append(findings, DLKFinding{Reason: DLKReasonOpenRedirect, Param: k, Value: host})
				}
			}
		}
		res.Params[k] = v
	}

	res.Safe = len(findings) == 0
	res.Findings = findings
	return res
}

func (r DLKResult) HasReason(reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func dlkStripScheme(raw, scheme string) (string, bool) {
	want := dlkLower(scheme) + ":"
	if len(raw) < len(want) {
		return "", false
	}
	if dlkLower(raw[:len(want)]) != want {
		return "", false
	}
	return raw[len(want):], true
}

func dlkParseQuery(q string) map[string]string {
	out := map[string]string{}
	if q == "" {
		return out
	}
	start := 0
	for i := 0; i <= len(q); i++ {
		if i == len(q) || q[i] == '&' {
			pair := q[start:i]
			if eq := dlkIndexByte(pair, '='); eq >= 0 {
				out[dlkPercentDecode(pair[:eq])] = dlkPercentDecode(pair[eq+1:])
			} else {
				out[dlkPercentDecode(pair)] = ""
			}
			start = i + 1
		}
	}
	return out
}

func dlkIndexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// dlkPercentDecode 仅做 %XX 解码（足够识别 %2e%2e/%5c 等编码绕过），非法序列保持原样。
func dlkPercentDecode(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok1 := dlkHex(s[i+1]); ok1 {
				if lo, ok2 := dlkHex(s[i+2]); ok2 {
					out = append(out, hi<<4|lo)
					i += 2
					continue
				}
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}

func dlkHex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

func dlkHasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}

func dlkPathEscapes(p string) bool {
	// 绝对盘符 / 根 / 含 .. 分量（含百分号解码后）
	if len(p) >= 2 && p[1] == ':' {
		return true
	}
	if len(p) >= 1 && (p[0] == '/' || p[0] == '\\') {
		return true
	}
	cur := ""
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' || p[i] == '\\' {
			if cur == ".." {
				return true
			}
			cur = ""
		} else {
			cur += string(p[i])
		}
	}
	return false
}

func dlkIsUNC(p string) bool {
	return len(p) >= 2 && (p[0:2] == `\\` || p[0:2] == "//")
}

func dlkURLScheme(u string) string {
	for i := 0; i < len(u); i++ {
		if u[i] == ':' {
			return dlkLower(u[:i])
		}
		if u[i] == '/' || u[i] == '\\' || u[i] == '?' {
			break
		}
	}
	return ""
}

func dlkURLHost(u string) string {
	idx := -1
	for i := 0; i+3 <= len(u); i++ {
		if u[i:i+3] == "://" {
			idx = i + 3
			break
		}
	}
	if idx < 0 {
		return ""
	}
	end := len(u)
	for i := idx; i < len(u); i++ {
		if u[i] == '/' || u[i] == '\\' || u[i] == '?' {
			end = i
			break
		}
	}
	host := u[idx:end]
	// 去掉 userinfo
	if at := dlkIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	return dlkLower(host)
}

func dlkLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}
