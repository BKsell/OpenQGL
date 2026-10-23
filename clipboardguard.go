package main

// clipboardguard.go —— 剪贴板内容粘贴到高敏输入框前的注入/诱导守卫。
//
// 背景：
//   用户会把剪贴板内容粘到服务器地址、Java 参数、实例名等输入框。剪贴板可被恶意网页/其它程序
//   预置，粘贴路径与键盘输入不同，会带入肉眼难辨的危险载荷：
//     - 命令行开关：粘贴的"服务器地址"其实是 "-javaagent:x.jar" 或带换行的多行 JVM 参数，
//       一旦进入命令构造即变成额外参数（参数注入）；
//     - 内嵌换行/回车：一次粘贴塞多段内容（CSV/参数注入，CRLF）；
//     - 危险 URL：file://、\\host\share（UNC 触发 NTLM）、javascript:、jar:；
//     - URL 内嵌账号密码 user:pass@host（凭据泄漏到第三方主机）；
//     - 富文本/HTML 走私：剪贴板里藏 <script>、ms-msdt:/ms-officecmd: 等唤起串；
//     - 超长粘贴（DoS 输入框/后续解析）、首尾空白伪装。
//   本模块纯字符判定，不读系统剪贴板（由 Wails 绑定拿到文本后调用），不使用正则。

const (
	CBReasonControlChar       = "clipboard-contains-control-char"
	CBReasonNewline           = "clipboard-multi-line-paste"
	CBReasonJVMFlagInjection  = "clipboard-jvm-flag-injection"
	CBReasonDangerousScheme   = "clipboard-dangerous-url-scheme"
	CBReasonUNCPath           = "clipboard-unc-path-credential-leak"
	CBReasonEmbeddedCreds     = "clipboard-url-embedded-credentials"
	CBReasonAppLauncher       = "clipboard-app-launcher-protocol"
	CBReasonHTMLSmuggling     = "clipboard-html-smuggling"
	CBReasonTooLong           = "clipboard-paste-too-long"
	CBReasonLeadingTrailSpace = "clipboard-leading-trailing-whitespace"
)

const CBMaxPasteBytes = 4096

// CBFinding 记录一处剪贴板风险。
type CBFinding struct {
	Reason string
	Detail string
}

// CBFieldKind 标识目标输入框类型，决定采用哪套规则。
type CBFieldKind int

const (
	CBFieldServerAddress CBFieldKind = iota
	CBFieldJVMArgs
	CBFieldInstanceName
	CBFieldGenericURL
)

// CBResult 审计结果。Sanitized 为去除首尾空白与控制字符后的建议展示文本。
type CBResult struct {
	Safe      bool
	Findings  []CBFinding
	Sanitized string
}

var cbDangerousSchemes = []string{"file:", "javascript:", "jar:", "netdoc:", "data:", "vbscript:"}
var cbLauncherProtocols = []string{
	"ms-msdt:", "ms-officecmd:", "ms-cxh:", "ms-callrec:",
	"search-ms:", "shell:", "vscode:", "jdwp:",
}

// CBAudit 审计粘贴文本。kind 指定目标输入框。
func CBAudit(text string, kind CBFieldKind) CBResult {
	var findings []CBFinding

	if len(text) > CBMaxPasteBytes {
		findings = append(findings, CBFinding{Reason: CBReasonTooLong,
			Detail: itoaCB(len(text))})
	}

	trimmed := cbTrimSpace(text)
	if trimmed != text {
		findings = append(findings, CBFinding{Reason: CBReasonLeadingTrailSpace})
	}

	lower := cbToLower(trimmed)

	// 控制字符（保留制表用于某些框，但换行一律单独记）
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c == '\n' || c == '\r' {
			findings = append(findings, CBFinding{Reason: CBReasonNewline})
			break
		}
	}
	if cbContainsControl(trimmed) {
		findings = append(findings, CBFinding{Reason: CBReasonControlChar})
	}

	// 粘贴到非 JVM 参数框却带 JVM 开关，判参数注入
	if kind != CBFieldJVMArgs {
		for _, flag := range cbJVMFlags {
			if cbContainsToken(lower, flag) {
				findings = append(findings, CBFinding{Reason: CBReasonJVMFlagInjection,
					Detail: flag})
				break
			}
		}
	}

	for _, s := range cbDangerousSchemes {
		if cbContainsToken(lower, s) {
			findings = append(findings, CBFinding{Reason: CBReasonDangerousScheme,
				Detail: s})
			break
		}
	}

	for _, p := range cbLauncherProtocols {
		if cbContainsToken(lower, p) {
			findings = append(findings, CBFinding{Reason: CBReasonAppLauncher,
				Detail: p})
			break
		}
	}

	// UNC 路径 \\host\share 或 //host/share
	if cbHasUNC(lower) {
		findings = append(findings, CBFinding{Reason: CBReasonUNCPath})
	}

	// URL 内嵌凭据 scheme://user:pass@
	if cbHasEmbeddedCreds(lower) {
		findings = append(findings, CBFinding{Reason: CBReasonEmbeddedCreds})
	}

	// HTML 走私标签/事件
	for _, frag := range cbHTMLFragments {
		if cbContainsToken(lower, frag) {
			findings = append(findings, CBFinding{Reason: CBReasonHTMLSmuggling,
				Detail: frag})
			break
		}
	}

	return CBResult{
		Safe:      len(findings) == 0,
		Findings:  findings,
		Sanitized: cbStripControl(trimmed),
	}
}

var cbJVMFlags = []string{
	"-javaagent", "-agentlib", "-agentpath", "-xbootclasspath",
	"-xx:+use", "-djava.library.path", "-djava.security.manager",
	"-djava.security.policy", "-dlog4j.configuration", "-agentlib:jdwp",
	"_java_options", "java_tool_options",
}

var cbHTMLFragments = []string{
	"<script", "onerror=", "onload=", "<iframe", "<object",
	"javascript:", "data:text/html",
}

func (r CBResult) HasReason(reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func cbTrimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && cbIsSpace(s[start]) {
		start++
	}
	for end > start && cbIsSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func cbIsSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == 0x0B || b == 0x0C
}

func cbContainsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
		if c == 0x7F {
			return true
		}
	}
	return false
}

func cbStripControl(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != 0x7F {
			out = append(out, c)
		}
	}
	return string(out)
}

func cbToLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

// cbContainsToken 判断 s 是否含子串 tok（纯字节包含；调用前已小写化）。
func cbContainsToken(s, tok string) bool {
	if len(tok) == 0 || len(tok) > len(s) {
		return false
	}
	for i := 0; i+len(tok) <= len(s); i++ {
		if s[i:i+len(tok)] == tok {
			return true
		}
	}
	return false
}

func cbHasUNC(s string) bool {
	// 反斜杠 UNC（\\host\share）会触发 Windows NTLM 凭据外发，一律提示。
	if cbContainsToken(s, `\\`) {
		return true
	}
	// 正斜杠 // 仅在"协议相对开头"（//host，且没有 :// 上下文）才算 UNC，
	// 避免把正常的 https://host 误报。
	if len(s) >= 2 && s[0:2] == "//" {
		return true
	}
	return false
}

func cbHasEmbeddedCreds(s string) bool {
	// 寻找 :// 之后、第一个 @ 之前是否含 ':'（user:pass@host）
	idx := -1
	for i := 0; i+3 <= len(s); i++ {
		if s[i:i+3] == "://" {
			idx = i + 3
			break
		}
	}
	if idx < 0 {
		return false
	}
	at := -1
	for i := idx; i < len(s); i++ {
		if s[i] == '@' {
			at = i
			break
		}
		if s[i] == '/' || s[i] == '\\' {
			break
		}
	}
	if at < 0 {
		return false
	}
	for i := idx; i < at; i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

func itoaCB(i int) string {
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
