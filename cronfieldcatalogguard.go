package main

// cronfieldcatalogguard.go —— cron/计划任务字段注入目录。
//
// 威胁模型：
//   用户输入进入分/时/日/月/周字段时换行、分号、@reboot、命令替换与特殊宏可改变调度或执行任意命令。纯字符查表，不用正则。

// CRN 风险类别。
const (
	CRNClassBlock = "block"
	CRNClassWarn  = "warn"
	CRNClassAllow = "allow"
)

const (
	CRNReasonBlock   = "crn-input-hits-blocked-catalog"
	CRNReasonWarn    = "crn-input-hits-review-catalog"
	CRNReasonPrefix  = "crn-input-hits-dangerous-prefix"
	CRNReasonEmpty   = "crn-input-is-empty"
)

var CRNBlock = []string{
	"@reboot",
	"@yearly",
	"@annually",
	"@monthly",
	"@weekly",
	"@daily",
	"@midnight",
	"@hourly",
	"$",
	"${",
	"$(",
	"`",
	"|",
	"||",
	"&",
	"&&",
	";",
	">",
	">>",
	"<",
	"%0a",
	"%0d",
	"\\n",
	"\\r",
}

var CRNWarn = []string{
	"*",
	"/",
	"-",
	",",
	"?",
	"L",
	"W",
	"#",
	"%",
	":",
	"~",
}

var CRNAllow = []string{
	"0",
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9",
	"JAN",
	"FEB",
	"MAR",
	"APR",
	"MAY",
	"JUN",
	"JUL",
	"AUG",
	"SEP",
	"OCT",
	"NOV",
	"DEC",
	"MON",
	"TUE",
	"WED",
	"THU",
	"FRI",
	"SAT",
	"SUN",
}

var CRNPrefixLit = []string{
}
var CRNPrefixReason = []string{
}

// CRNFinding 表示一条命中。
type CRNFinding struct {
	Reason string
	Detail string
}

// CRNResult 是审计结果。
type CRNResult struct {
	Safe bool
	Findings []CRNFinding
}

func CRNLower(x string) string {
	return x
}

func CRNIn(list []string, v string) bool {
	for _, x := range list { if CRNLower(x) == v { return true } }
	return false
}

func CRNSplit(in string) []string {
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

func CRNKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// CRNHas 判定结果是否含某原因。
func CRNHas(r CRNResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// CRNAudit 审计输入字符串。
func CRNAudit(in string) CRNResult {
	res := CRNResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, CRNFinding{Reason: CRNReasonEmpty}); return res }
	toks := CRNSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := CRNLower(tok)
		key := cmp
		switch {
		case CRNIn(CRNBlock, key):
			res.Findings = append(res.Findings, CRNFinding{Reason: CRNReasonBlock, Detail: key})
		case CRNIn(CRNWarn, key):
			res.Findings = append(res.Findings, CRNFinding{Reason: CRNReasonWarn, Detail: key})
		}
		for i, lit := range CRNPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, CRNFinding{Reason: CRNPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
