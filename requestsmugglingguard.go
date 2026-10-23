package main

// requestsmugglingguard.go —— 出向 HTTP 请求的 CL/TE 走私（HTTP Request Smuggling）预检。
//
// 背景：
//   启动器虽以 HTTP 客户端为主，但会经由本地/自建代理、更新中转、调试代理发送请求；也会构造
//   multipart、分块上传。请求头若同时带 Content-Length 与 Transfer-Encoding，或重复/畸形，就会在
//   "前端代理"与"后端"按不同规则解析边界时产生请求走私，把后续请求拼接到攻击者控制的前缀里：
//     - 同时存在 CL 与 TE（CL.TE / TE.CL 歧义）；
//     - 多个 Content-Length（含空格、逗号、不同取值）；
//     - 畸形 TE（"chunked" 之外塞其它编码、大小写/空白混淆绕过只做精确匹配的代理）；
//     - TE: identity 与 chunked 并存；CL 为非法/负数/非十进制；
//     - 头部名/值里的 CR/LF（响应/请求拆分 CRLF injection）。
//   本模块对"已构造的请求头集合"做静态预检（调用方把头部以名/值喂入），纯字符串判定，不用正则。

const (
	RSReasonCLandTE             = "smuggling-content-length-and-transfer-encoding"
	RSReasonDuplicateCL         = "smuggling-duplicate-content-length"
	RSReasonConflictingCL       = "smuggling-conflicting-content-length-values"
	RSReasonInvalidCL           = "smuggling-invalid-content-length"
	RSReasonMalformedTE         = "smuggling-malformed-transfer-encoding"
	RSReasonMultipleTE          = "smuggling-multiple-transfer-encoding"
	RSReasonTEWithIdentity      = "smuggling-transfer-encoding-mixed-identity"
	RSReasonHeaderCRLF          = "smuggling-header-name-or-value-crlf"
	RSReasonObsoleteLineFolding = "smuggling-obsolete-line-folding"
)

// RSHeader 是一条请求头（名/值）。
type RSHeader struct {
	Name  string
	Value string
}

// RSFinding 记录一处走私/拆分风险。
type RSFinding struct {
	Reason string
	Detail string
}

// RSAuditRequestHeaders 审计出向请求头。
func RSAuditRequestHeaders(headers []RSHeader) (safe bool, findings []RSFinding) {
	clValues := []string{}
	teCount := 0
	var teValues []string

	for _, h := range headers {
		name := rsToLower(h.Name)

		if rsHasCRLF(h.Name) {
			findings = append(findings, RSFinding{Reason: RSReasonHeaderCRLF, Detail: "name"})
		}
		if rsHasCRLF(h.Value) {
			findings = append(findings, RSFinding{Reason: RSReasonHeaderCRLF, Detail: "value:" + name})
			if rsHasObsoleteFold(h.Value) {
				findings = append(findings, RSFinding{Reason: RSReasonObsoleteLineFolding, Detail: name})
			}
		}

		switch name {
		case "content-length":
			clValues = append(clValues, rsTrim(h.Value))
		case "transfer-encoding":
			teCount++
			teValues = append(teValues, rsTrim(h.Value))
		}
	}

	// CL 多条
	if len(clValues) > 1 {
		findings = append(findings, RSFinding{Reason: RSReasonDuplicateCL})
		same := true
		for _, v := range clValues[1:] {
			if v != clValues[0] {
				same = false
			}
		}
		if !same {
			findings = append(findings, RSFinding{Reason: RSReasonConflictingCL})
		}
	}
	for _, v := range clValues {
		if !rsIsValidCL(v) {
			findings = append(findings, RSFinding{Reason: RSReasonInvalidCL, Detail: v})
		}
	}

	// TE 多条
	if teCount > 1 {
		findings = append(findings, RSFinding{Reason: RSReasonMultipleTE})
	}
	for _, v := range teValues {
		if rsTEHasIdentity(v) {
			findings = append(findings, RSFinding{Reason: RSReasonTEWithIdentity, Detail: v})
		}
		if !rsTEAllowsChunkedOnly(v) {
			findings = append(findings, RSFinding{Reason: RSReasonMalformedTE, Detail: v})
		}
	}

	// CL 与 TE 同时存在（即便 TE 合法）也是走私歧义，必须二选一
	if len(clValues) > 0 && teCount > 0 {
		findings = append(findings, RSFinding{Reason: RSReasonCLandTE})
	}

	return len(findings) == 0, findings
}

func rsIsValidCL(v string) bool {
	if v == "" {
		return false
	}
	// 允许单个十进制非负整数；不允许前导空格（已 trim）、负号、多值、十六进制
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	// 前导 0 的多位数字（012）虽可解析但属异常，保守拒绝以统一边界
	if len(v) > 1 && v[0] == '0' {
		return false
	}
	return true
}

// rsTEAllowsChunkedOnly 允许 "chunked" 或 "chunked, chunked" 之外的规范组合吗？
// 这里采取最严格策略：值去除空白与大小写后必须严格等于 chunked。
func rsTEAllowsChunkedOnly(v string) bool {
	return rsToLower(rsStripSpace(v)) == "chunked"
}

func rsTEHasIdentity(v string) bool {
	// 逗号分隔的编码项里出现 identity 与 chunked 混用
	for _, tok := range rsSplitComma(v) {
		if rsToLower(rsStripSpace(tok)) == "identity" {
			return true
		}
	}
	return false
}

func rsHasCRLF(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return true
		}
	}
	return false
}

func rsHasObsoleteFold(s string) bool {
	// 废弃折行：CR/LF 之后紧跟空格或制表（且该 CR/LF 已确认存在）。
	for i := 0; i+1 < len(s); i++ {
		if (s[i] == '\r' || s[i] == '\n') && (s[i+1] == ' ' || s[i+1] == '\t') {
			return true
		}
	}
	return false
}

func rsSplitComma(s string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	out = append(out, cur)
	return out
}

func rsStripSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func rsTrim(s string) string {
	return rsStripSpace(s)
}

func rsToLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

// RSHasReason 判定结果含某类问题。
func RSHasReason(findings []RSFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
