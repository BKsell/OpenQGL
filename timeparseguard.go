package main

// timeparseguard.go —— 外部时间/时间戳字段的安全解析守卫。
//
// 背景：
//   启动器解析版本发布时间、证书 NotAfter、HTTP Date、存档 mtime。风险：
//     - 秒/毫秒/微秒单位混淆，把毫秒当秒得到远未来时间，绕过"证书未过期/令牌未到期"判断；
//     - 负时间戳、超大年导致 time.Unix 后年份溢出或比较异常；
//     - RFC3339 缺时区（裸时间）被按本地时解释，跨时区造成宽限/拒绝偏差；
//     - 2 月 30 日、星期与日期不一致等非法日历日期；
//     - 仅日期被当作 00:00:00，边界判断差一整天。
//   纯数值/字符判定，不使用正则。

const (
	TPReasonUnitAmbiguous   = "timestamp-unit-seconds-vs-millis-ambiguous"
	TPReasonOutOfRange      = "timestamp-out-of-supported-year-range"
	TPReasonMissingTimezone = "rfc3339-datetime-missing-timezone-designator"
	TPReasonInvalidCalendar = "calendar-date-not-a-real-day"
	TPReasonNegativeEpoch   = "negative-unix-epoch-timestamp"
)

// TPFinding 记录一处问题。
type TPFinding struct {
	Reason string
	Detail string
}

const (
	// TPMinYear / TPMaxYear 限定可安全处理的年份。
	TPMinYear = 1970
	TPMaxYear = 2200
)

// TPAuditEpoch 审计一个"可能是秒或毫秒"的 epoch 整数。
// isMillisHint=true 表示来源字段名/上下文明确是毫秒；false 表示裸数值需推断。
func TPAuditEpoch(v int64, isMillisHint bool) (safe bool, seconds int64, isMillis bool, findings []TPFinding) {
	if v < 0 {
		findings = append(findings, TPFinding{Reason: TPReasonNegativeEpoch})
	}
	val := v
	if isMillisHint {
		isMillis = true
		val = v / 1000
	} else {
		// 秒级时间戳到 2200 年约 7.25e9；毫秒级约 7.25e12。
		// 超过 1e11 的裸值几乎必然是毫秒被误当秒。
		if v > 100_000_000_000 {
			isMillis = true
			val = v / 1000
			findings = append(findings, TPFinding{Reason: TPReasonUnitAmbiguous,
				Detail: "auto-detected-millis"})
		}
	}
	year := tpEpochYearApprox(val)
	if year < TPMinYear || year > TPMaxYear {
		findings = append(findings, TPFinding{Reason: TPReasonOutOfRange,
			Detail: tpItoa(int64(year))})
	}
	return len(findings) == 0, val, isMillis, findings
}

// TPAuditRFC3339 判定一个日期时间串是否带时区设计符（末尾 Z 或 ±hh:mm）。
func TPAuditRFC3339(s string) (safe bool, findings []TPFinding) {
	if !tpHasDateShape(s) {
		return true, nil // 非完整日期时间不在此函数管辖
	}
	if tpHasTimezone(s) {
		return true, nil
	}
	return false, []TPFinding{{Reason: TPReasonMissingTimezone, Detail: s}}
}

// TPAuditCalendarDate 校验 YYYY-MM-DD 是否为真实存在的日期。
func TPAuditCalendarDate(year, month, day int) (safe bool, findings []TPFinding) {
	if year < TPMinYear || year > TPMaxYear {
		findings = append(findings, TPFinding{Reason: TPReasonOutOfRange,
			Detail: tpItoa(int64(year))})
	}
	if month < 1 || month > 12 || day < 1 {
		findings = append(findings, TPFinding{Reason: TPReasonInvalidCalendar})
		return len(findings) == 0, findings
	}
	if day > tpDaysInMonth(year, month) {
		findings = append(findings, TPFinding{Reason: TPReasonInvalidCalendar,
			Detail: tpItoa(int64(year)) + "-" + tpItoa(int64(month)) + "-" + tpItoa(int64(day))})
	}
	return len(findings) == 0, findings
}

func tpEpochYearApprox(sec int64) int {
	// 近似：每年 365.2425 天
	if sec < 0 {
		return TPMinYear - 1
	}
	return TPMinYear + int(sec/31556952)
}

func tpDaysInMonth(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if tpIsLeap(year) {
			return 29
		}
		return 28
	}
	return 0
}

func tpIsLeap(year int) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

// tpHasDateShape：至少形如 YYYY-MM-DD
func tpHasDateShape(s string) bool {
	if len(s) < 10 {
		return false
	}
	for i := 0; i < 4; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	if s[4] != '-' || s[7] != '-' {
		return false
	}
	for _, i := range []int{5, 6, 8, 9} {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func tpHasTimezone(s string) bool {
	if tpHasSuffix(s, "Z") || tpHasSuffix(s, "z") {
		return true
	}
	// 找 ±hh:mm 结尾
	for i := len(s) - 6; i >= 0; i-- {
		if (s[i] == '+' || s[i] == '-') && s[i+3] == ':' {
			return true
		}
	}
	return false
}

func tpHasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

func tpItoa(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TPHasReason 判定结果含某类问题。
func TPHasReason(findings []TPFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
