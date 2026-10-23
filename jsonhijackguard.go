package main

// jsonhijackguard.go —— JSON 响应的内容类型与"可执行前缀/数组劫持"防护。
//
// 背景：
//   启动器拉取版本清单、服务器列表、皮肤/玩家信息等 JSON。历史浏览器可通过覆盖 Array/Object 构造器，
//   用 <script src=jsonurl> 跨站读取顶层为数组的 JSON（JSON hijacking）。相关缺陷：
//     - JSON 以 text/html 等可被当文档解析的类型下发，或类型缺失触发 MIME 嗅探成脚本；
//     - 顶层为裸数组/对象，且可被跨站 <script> 加载（无可执行前缀防护、无 X-Content-Type-Options）；
//     - JSONP 包装（callback(...)）把敏感数据交给任意来源调用；
//     - 内容以可执行 token 开头（被当脚本时即运行）。
//   纯字节前缀/类型判定，不解析 JSON、不使用正则。

const (
	JHReasonContentTypeSniffable = "json-response-sniffable-or-html-content-type"
	JHReasonMissingNosniff       = "json-response-missing-x-content-type-options-nosniff"
	JHReasonTopLevelArray        = "json-response-top-level-array-script-readable"
	JHReasonJSONPWrapper         = "json-response-served-with-jsonp-callback-wrapper"
	JHReasonExecutablePrefix     = "json-body-starts-with-executable-token"
)

// JHResponse 描述一个 JSON 响应。
type JHResponse struct {
	ContentType      string
	HasNosniffHeader bool
	// BodyPrefix 为响应体去除前导空白后的前若干字节（调用方取前 64 字节即可）。
	BodyPrefix string
}

// JHFinding 记录一处 JSON 劫持风险。
type JHFinding struct {
	Reason string
}

// JHAuditResponse 审计 JSON 响应。
// allowTopLevelArray 为 true 时（同源且 nosniff + 正确类型）不把裸数组记为高危。
func JHAuditResponse(resp JHResponse, allowTopLevelArray bool) (safe bool, findings []JHFinding) {
	ct := jhLower(jhTrim(resp.ContentType))
	jsonType := jhHasPrefix(ct, "application/json") ||
		jhHasPrefix(ct, "application/problem+json")
	if !jsonType {
		findings = append(findings, JHFinding{Reason: JHReasonContentTypeSniffable})
	}
	if !resp.HasNosniffHeader {
		findings = append(findings, JHFinding{Reason: JHReasonMissingNosniff})
	}

	body := jhLstrip(resp.BodyPrefix)

	if body != "" {
		switch body[0] {
		case '[':
			if !allowTopLevelArray {
				findings = append(findings, JHFinding{Reason: JHReasonTopLevelArray})
			}
		case '{':
			// 顶层对象在现代浏览器上不可被脚本直接读取，可接受
		default:
			if jhLooksLikeJSONP(body) {
				findings = append(findings, JHFinding{Reason: JHReasonJSONPWrapper})
			} else if jhStartsExecutable(body) {
				findings = append(findings, JHFinding{Reason: JHReasonExecutablePrefix})
			}
		}
	}

	return len(findings) == 0, findings
}

// jhLooksLikeJSONP 粗判 "identifier(" / "obj.method(" 形式的 JSONP 包装。
func jhLooksLikeJSONP(body string) bool {
	i := 0
	// 标识符首字符
	if i >= len(body) || !jhIdentStart(body[i]) {
		return false
	}
	i++
	for i < len(body) {
		c := body[i]
		if jhIdentPart(c) {
			i++
			continue
		}
		if c == '.' {
			// 允许一段 a.b.c
			i++
			if i >= len(body) || !jhIdentStart(body[i]) {
				return false
			}
			i++
			continue
		}
		break
	}
	// 跳过标识符后必须紧跟 '('
	return i < len(body) && body[i] == '('
}

func jhStartsExecutable(body string) bool {
	tokens := []string{"function", "var ", "let ", "const ", "//", "/*", "+[", "-["}
	for _, tok := range tokens {
		if jhHasPrefix(body, tok) {
			return true
		}
	}
	return false
}

func jhIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func jhIdentPart(c byte) bool {
	return jhIdentStart(c) || (c >= '0' && c <= '9')
}

func jhLstrip(s string) string {
	i := 0
	// UTF-8 BOM (EF BB BF)
	if len(s) >= 3 && s[0] == 0xef && s[1] == 0xbb && s[2] == 0xbf {
		i = 3
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return s[i:]
}

func jhTrim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func jhLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func jhHasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}

// JHHasReason 判定结果含某类问题。
func JHHasReason(findings []JHFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
