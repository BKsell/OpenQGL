package main

// logforgerycatalogguard.go —— 日志伪造控制字符目录。
//
// 威胁模型：
//   写入日志的外部输入含 CR/LF/制表/换页/ANSI 转义可伪造日志行或注入终端转义。本目录收录控制字符令牌，
//   纯字符查表，写入前据此转义，不用正则。

// LFC 风险类别。
const (
	LFCClassBlock = "block"
	LFCClassWarn  = "warn"
	LFCClassAllow = "allow"
)

const (
	LFCReasonBlock   = "lfc-input-hits-blocked-catalog"
	LFCReasonWarn    = "lfc-input-hits-review-catalog"
	LFCReasonPrefix  = "lfc-input-hits-dangerous-prefix"
	LFCReasonEmpty   = "lfc-input-is-empty"
)

var LFCBlock = []string{
	"%0d%0a",
	"%0a",
	"%0d",
	"\\r\\n",
	"\\n",
	"\\r",
	"\\u000d\\u000a",
	"\\u000a",
	"\\u000d",
	"%0b",
	"%0c",
	"%1b",
	"\\u001b",
	"\\x1b",
	"\\x0b",
	"\\x0c",
	"%09",
	"\\t",
	"%00",
	"\\x00",
	"\\u0000",
	"%1b[",
	"\\u001b[",
	"ANSI",
	"esc[",
	"escape[",
	"crlf",
	"%0d%0aINFO",
	"%0d%0aERROR",
	"%0aWARN",
	"forge",
	"inject",
	"header-injection",
	"log-injection",
}

var LFCWarn = []string{
	"%20",
	"space",
	"pipe",
	"bracket",
	"gt",
	"lt",
	"amp",
	"quote",
	"backtick",
	"dollar",
	"percent",
	"control",
	"nonprint",
	"highbyte",
	"unicode",
	"emoji",
	"zero-width",
	"soft-hyphen",
	"bidi",
	"rtl",
	"lrm",
	"rlm",
	"nbsp",
}

var LFCAllow = []string{
	"[",
	"]",
	"-",
	":",
	",",
	".",
	"_",
	"@",
	"plain",
	"ascii",
	"timestamp",
	"level",
	"message",
	"logger",
	"thread",
	"mdc",
	"ndc",
}

var LFCPrefixLit = []string{
}
var LFCPrefixReason = []string{
}

// LFCFinding 表示一条命中。
type LFCFinding struct {
	Reason string
	Detail string
}

// LFCResult 是审计结果。
type LFCResult struct {
	Safe bool
	Findings []LFCFinding
}

func LFCLower(x string) string {
	return x
}

func LFCIn(list []string, v string) bool {
	for _, x := range list { if LFCLower(x) == v { return true } }
	return false
}

func LFCSplit(in string) []string {
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

func LFCKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// LFCHas 判定结果是否含某原因。
func LFCHas(r LFCResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// LFCAudit 审计输入字符串。
func LFCAudit(in string) LFCResult {
	res := LFCResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, LFCFinding{Reason: LFCReasonEmpty}); return res }
	toks := LFCSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := LFCLower(tok)
		key := cmp
		switch {
		case LFCIn(LFCBlock, key):
			res.Findings = append(res.Findings, LFCFinding{Reason: LFCReasonBlock, Detail: key})
		case LFCIn(LFCWarn, key):
			res.Findings = append(res.Findings, LFCFinding{Reason: LFCReasonWarn, Detail: key})
		}
		for i, lit := range LFCPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, LFCFinding{Reason: LFCPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
