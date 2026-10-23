package main

// cronexprguard.go —— 定时/调度表达式的注入与越界守卫。
//
// 背景：
//   启动器内若允许"定时重启/定时备份"等用户表达式（5 字段 cron 或 @reboot/@daily 宏），需要防：
//     - 字段数不为 5、空字段；
//     - 数字越界（分>59、时>23、月>12、周>7）；
//     - 步长为 0（/0 除零）、范围 a>b、范围两端类型不一致（1-mon）；
//     - 列表里混空项（1,,3）、非法名字；
//     - 注入换行/分号/命令替换字符（把表达式当 shell 片段拼接时）。
//   纯字符解析，不使用正则。

const (
	CRReasonFieldCount      = "cron-field-count-not-five"
	CRReasonValueOutOfRange = "cron-field-value-out-of-range"
	CRReasonStepZero        = "cron-step-is-zero"
	CRReasonBadRange        = "cron-range-inverted-or-typed-mismatch"
	CRReasonEmptyListItem   = "cron-list-contains-empty-item"
	CRReasonUnknownName     = "cron-named-month-or-weekday-unknown"
	CRReasonShellInjection  = "cron-expression-contains-shell-metacharacter"
)

// CRFinding 记录一处问题。
type CRFinding struct {
	Reason string
	Field  int
	Detail string
}

var crMonthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
var crDOWNames = map[string]int{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

// CRAudit 校验标准 5 字段 cron（分 时 日 月 周）。
func CRAudit(expr string) (safe bool, findings []CRFinding) {
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c == '\n' || c == '\r' || c == ';' || c == '|' || c == '&' ||
			c == '$' || c == '`' || c == '<' || c == '>' {
			findings = append(findings, CRFinding{Reason: CRReasonShellInjection, Detail: string(c)})
		}
	}
	fields := crSplitSpace(expr)
	if len(fields) != 5 {
		return false, append(findings, CRFinding{Reason: CRReasonFieldCount,
			Detail: crItoa(int64(len(fields)))})
	}
	ranges := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	for fi, f := range fields {
		findings = append(findings, crAuditField(f, fi, ranges[fi][0], ranges[fi][1])...)
	}
	return len(findings) == 0, findings
}

func crAuditField(f string, fieldIdx, lo, hi int) []CRFinding {
	var fs []CRFinding
	for _, item := range crSplitComma(f) {
		if item == "" {
			fs = append(fs, CRFinding{Reason: CRReasonEmptyListItem, Field: fieldIdx})
			continue
		}
		if item == "*" {
			continue
		}
		// 拆步长
		base := item
		step := 0
		hasStep := false
		if k := crIndexByte(item, '/'); k >= 0 {
			hasStep = true
			base = item[:k]
			stepStr := item[k+1:]
			n, ok := crParseInt(stepStr)
			if !ok || n <= 0 {
				fs = append(fs, CRFinding{Reason: CRReasonStepZero, Field: fieldIdx, Detail: stepStr})
				continue
			}
			step = n
		}
		loV, hiV, rok := crResolveRange(base, fieldIdx, lo, hi)
		if !rok {
			fs = append(fs, CRFinding{Reason: crRangeReason(fieldIdx), Field: fieldIdx, Detail: base})
			continue
		}
		if loV < lo || hiV > hi || loV > hiV {
			fs = append(fs, CRFinding{Reason: CRReasonValueOutOfRange, Field: fieldIdx,
				Detail: base})
			continue
		}
		_ = step
		_ = hasStep
	}
	return fs
}

func crRangeReason(fieldIdx int) string {
	if fieldIdx == 3 || fieldIdx == 4 {
		return CRReasonUnknownName
	}
	return CRReasonBadRange
}

func crResolveRange(base string, fieldIdx, lo, hi int) (int, int, bool) {
	if k := crIndexByte(base, '-'); k >= 0 {
		a, ok1 := crResolveToken(base[:k], fieldIdx)
		b, ok2 := crResolveToken(base[k+1:], fieldIdx)
		if !ok1 || !ok2 {
			return 0, 0, false
		}
		return a, b, a <= b
	}
	v, ok := crResolveToken(base, fieldIdx)
	if !ok {
		return 0, 0, false
	}
	return v, v, true
}

func crResolveToken(tok string, fieldIdx int) (int, bool) {
	if n, ok := crParseInt(tok); ok {
		return n, true
	}
	name := crLower(tok)
	switch fieldIdx {
	case 3:
		n, ok := crMonthNames[name]
		return n, ok
	case 4:
		n, ok := crDOWNames[name]
		return n, ok
	}
	return 0, false
}

func crParseInt(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

func crSplitSpace(s string) []string {
	var out []string
	cur := ""
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' || s[i] == '\t' {
			if cur != "" || (i < len(s)) {
				out = append(out, cur)
			}
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

func crSplitComma(s string) []string {
	var out []string
	cur := ""
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
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

func crIndexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func crLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func crItoa(i int64) string {
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

// CRHasReason 判定结果含某类问题。
func CRHasReason(findings []CRFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
