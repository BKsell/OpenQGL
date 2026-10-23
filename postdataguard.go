package main

// postdataguard.go —— 出向请求体（POST/PUT/PATCH）体积、类型与敏感字段守卫。
//
// 背景：
//   启动器会向登录/验证/上传接口提交表单与 JSON。请求体处理的风险：
//     - 无上限的 body：对端或本地代理被超大载荷拖垮（放大 DoS），内存暴涨；
//     - 声明 Content-Type 与实际载荷不符（声明 text 却发 JSON / multipart），绕过仅按类型的校验；
//     - 密码/令牌放进 URL query 或被拼进会被日志记录的字段；
//     - multipart 未带 boundary 或 boundary 过长/含 CR；
//   纯数值与字符串判定，不使用正则。

const (
	PDReasonBodyExceedsLimit       = "request-body-exceeds-declared-limit"
	PDReasonDeclaredLengthMismatch = "request-body-declared-length-mismatch"
	PDReasonContentTypeMismatch    = "request-content-type-does-not-match-body"
	PDReasonSecretInURL            = "request-secret-placed-in-url-query"
	PDReasonMissingBoundary        = "multipart-content-type-missing-boundary"
	PDReasonBoundaryBad            = "multipart-boundary-too-long-or-crlf"
	PDReasonEmptyMethodBody        = "request-method-forbids-payload-body"
)

// PDFinding 记录一处请求体风险。
type PDFinding struct {
	Reason string
	Detail string
}

// PDRequest 描述一次出向请求。
type PDRequest struct {
	Method       string
	ContentType  string
	BodyBytes    int64
	DeclaredLen  int64 // -1 表示未知
	MaxBodyBytes int64
	URLQuery     string // '?' 之后部分，用于检查是否夹带敏感字段
}

// PDAuditRequest 审计请求体。
func PDAuditRequest(req PDRequest) (safe bool, findings []PDFinding) {
	method := pdUpper(req.Method)

	switch method {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		if req.BodyBytes > 0 {
			findings = append(findings, PDFinding{Reason: PDReasonEmptyMethodBody})
		}
	}

	if req.MaxBodyBytes > 0 && req.BodyBytes > req.MaxBodyBytes {
		findings = append(findings, PDFinding{Reason: PDReasonBodyExceedsLimit,
			Detail: pdItoa(req.BodyBytes)})
	}
	if req.DeclaredLen >= 0 && req.DeclaredLen != req.BodyBytes {
		findings = append(findings, PDFinding{Reason: PDReasonDeclaredLengthMismatch})
	}

	ct := pdLower(req.ContentType)
	if pdHasPrefix(ct, "multipart/") {
		boundary := pdExtractBoundary(ct)
		if boundary == "" {
			findings = append(findings, PDFinding{Reason: PDReasonMissingBoundary})
		} else if len(boundary) > 70 || pdContainsCR(boundary) {
			findings = append(findings, PDFinding{Reason: PDReasonBoundaryBad})
		}
		if req.BodyBytes == 0 {
			findings = append(findings, PDFinding{Reason: PDReasonContentTypeMismatch,
				Detail: "multipart-with-empty-body"})
		}
	}
	if pdHasPrefix(ct, "application/json") && req.BodyBytes == 0 {
		findings = append(findings, PDFinding{Reason: PDReasonContentTypeMismatch,
			Detail: "json-with-empty-body"})
	}

	for _, key := range []string{"password", "passwd", "client_secret", "access_token",
		"refresh_token", "id_token"} {
		if pdQueryHasKey(req.URLQuery, key) {
			findings = append(findings, PDFinding{Reason: PDReasonSecretInURL, Detail: key})
		}
	}

	return len(findings) == 0, findings
}

// pdQueryHasKey 检查 query 中是否存在某键（支持 ?a=b&key= 与百分号编码键）。
func pdQueryHasKey(query, key string) bool {
	i := 0
	for i < len(query) {
		j := i
		for j < len(query) && query[j] != '&' {
			j++
		}
		pair := query[i:j]
		eq := pdIndexByte(pair, '=')
		k := pair
		if eq >= 0 {
			k = pair[:eq]
		}
		k = pdPercentDecode(pdLower(k))
		if k == key {
			return true
		}
		i = j + 1
	}
	return false
}

func pdExtractBoundary(ct string) string {
	const marker = "boundary="
	idx := pdIndexStr(ct, marker)
	if idx < 0 {
		return ""
	}
	rest := ct[idx+len(marker):]
	end := pdIndexByte(rest, ';')
	if end >= 0 {
		rest = rest[:end]
	}
	return pdTrimSpace(rest)
}

func pdPercentDecode(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if h, ok := pdHex(s[i+1], s[i+2]); ok {
				out = append(out, h)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}

func pdHex(a, b byte) (byte, bool) {
	hv := pdHexVal(a)
	lv := pdHexVal(b)
	if hv < 0 || lv < 0 {
		return 0, false
	}
	return byte(hv<<4 | lv), true
}

func pdHexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return -1
	}
}

func pdContainsCR(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return true
		}
	}
	return false
}

func pdHasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}

func pdIndexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func pdIndexStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func pdTrimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func pdLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func pdUpper(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 0x20
		}
	}
	return string(b)
}

func pdItoa(i int64) string {
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

// PDHasReason 判定结果含某类问题。
func PDHasReason(findings []PDFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
