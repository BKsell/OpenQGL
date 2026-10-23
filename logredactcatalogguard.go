package main

// logredactcatalogguard.go —— 日志脱敏键名/标签目录。
//
// 威胁模型：
//   崩溃日志、抓包、审计落盘会带上头与表单。本模块维护必须脱敏的字段目录及命名片段，供写日志前替换，
//   纯字符匹配，不用正则。

// LRC 风险类别。
const (
	LRCClassBlock = "block"
	LRCClassWarn  = "warn"
	LRCClassAllow = "allow"
)

const (
	LRCReasonBlock   = "lrc-input-hits-blocked-catalog"
	LRCReasonWarn    = "lrc-input-hits-review-catalog"
	LRCReasonPrefix  = "lrc-input-hits-dangerous-prefix"
	LRCReasonEmpty   = "lrc-input-is-empty"
)

var LRCBlock = []string{
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"x-auth-token",
	"password",
	"passwd",
	"secret",
	"client_secret",
	"access_token",
	"refresh_token",
	"id_token",
	"private_key",
	"card_number",
	"cvv",
	"cvc",
	"ssn",
	"credit_card",
	"iban",
	"bic",
	"routing_number",
}

var LRCWarn = []string{
	"email",
	"phone",
	"first_name",
	"last_name",
	"display_name",
	"ip",
	"x-forwarded-for",
	"device_id",
	"session_id",
	"latitude",
	"longitude",
	"postal_code",
	"address",
	"birthdate",
}

var LRCAllow = []string{
	"timestamp",
	"level",
	"event",
	"version",
	"os",
	"arch",
	"java_version",
	"ram",
	"duration_ms",
	"status_code",
}

var LRCPrefixLit = []string{
	"token",
	"secret",
	"password",
	"card",
	"authorization",
}
var LRCPrefixReason = []string{
	"log-key-may-be-token",
	"log-key-may-be-secret",
	"log-key-may-be-password",
	"log-key-may-be-card",
	"log-key-may-be-authorization",
}

// LRCFinding 表示一条命中。
type LRCFinding struct {
	Reason string
	Detail string
}

// LRCResult 是审计结果。
type LRCResult struct {
	Safe bool
	Findings []LRCFinding
}

func LRCLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func LRCIn(list []string, v string) bool {
	for _, x := range list { if LRCLower(x) == v { return true } }
	return false
}

func LRCSplit(in string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(in); i++ {
		end := i == len(in)
		sep := false
		if !end { c := in[i]; sep = c == ' ' || c == '\t' || c == '\n' || c == '\r' }
		if end || sep {
			if start >= 0 { out = append(out, in[start:i]); start = -1 }
		} else if start < 0 {
			start = i
		}
	}
	return out
}

func LRCKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// LRCHas 判定结果是否含某原因。
func LRCHas(r LRCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// LRCAudit 审计输入字符串。
func LRCAudit(in string) LRCResult {
	res := LRCResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, LRCFinding{Reason: LRCReasonEmpty}); return res }
	toks := LRCSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := LRCLower(tok)
		key := cmp
		switch {
		case LRCIn(LRCBlock, key):
			res.Findings = append(res.Findings, LRCFinding{Reason: LRCReasonBlock, Detail: key})
		case LRCIn(LRCWarn, key):
			res.Findings = append(res.Findings, LRCFinding{Reason: LRCReasonWarn, Detail: key})
		}
		for i, lit := range LRCPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, LRCFinding{Reason: LRCPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
