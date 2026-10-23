package main

// integerparseguard.go —— 外部数字字段（大小/偏移/数量/内存）的安全解析与溢出守卫。
//
// 背景：
//   启动器解析版本清单、mod 元数据、服务器 MOTD 数字、JVM 内存参数等外部数字。风险：
//     - 负数被当作无符号大小（-1 → 超大无符号，分配/拷贝爆内存）；
//     - 超大值在乘元素大小（如 count * recordSize）时整数溢出，绕过上限检查后小块拷贝；
//     - 单位后缀（K/M/G）解析错误或被注入；前导正负号/空白/十六进制混用；
//     - count 与 length 组合不一致（声明 100 项但缓冲只够 2 项）。
//   本模块做有界解析与乘法溢出检查，所有计算 int64，不使用正则。

const (
	IPReasonEmpty         = "integer-empty-or-non-numeric"
	IPReasonNegative      = "integer-negative-used-as-size"
	IPReasonOverflow      = "integer-overflow-int64"
	IPReasonBadSuffix     = "integer-unit-suffix-invalid"
	IPReasonMulOverflow   = "integer-multiplication-overflow"
	IPReasonCountMismatch = "integer-declared-count-exceeds-available-records"
	IPReasonExceedsMax    = "integer-exceeds-configured-maximum"
)

// IPResult 是解析结果。
type IPResult struct {
	Value   int64
	OK      bool
	Reasons []string
}

// IPParseSize 解析非负整数，支持可选 K/M/G（1024 进制）后缀，强制不超 int64、不超 max。
func IPParseSize(s string, max int64) IPResult {
	if s == "" {
		return IPResult{Reasons: []string{IPReasonEmpty}}
	}
	var n int64
	i := 0
	started := false
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		started = true
		d := int64(s[i] - '0')
		if n > (1<<63-1-d)/10 {
			return IPResult{Reasons: []string{IPReasonOverflow}}
		}
		n = n*10 + d
		i++
	}
	if !started {
		return IPResult{Reasons: []string{IPReasonEmpty}}
	}
	rest := s[i:]
	if rest != "" {
		mult := int64(0)
		switch rest {
		case "K", "k":
			mult = 1 << 10
		case "M", "m":
			mult = 1 << 20
		case "G", "g":
			mult = 1 << 30
		default:
			return IPResult{Reasons: []string{IPReasonBadSuffix}}
		}
		if n > (1<<63-1)/mult {
			return IPResult{Reasons: []string{IPReasonMulOverflow}}
		}
		n *= mult
	}
	if max >= 0 && n > max {
		return IPResult{Value: n, Reasons: []string{IPReasonExceedsMax}}
	}
	return IPResult{Value: n, OK: true}
}

// IPCheckedMul 在不溢出 int64 的前提下计算 a*b。
func IPCheckedMul(a, b int64) (result int64, overflow bool) {
	if a == 0 || b == 0 {
		return 0, false
	}
	if a < 0 || b < 0 {
		return 0, true
	}
	if a > (1<<63-1)/b {
		return 0, true
	}
	return a * b, false
}

// IPRejectNegative 把可能为负的"大小类"值收口。
func IPRejectNegative(n int64) (safe bool, reason string) {
	if n < 0 {
		return false, IPReasonNegative
	}
	return true, ""
}

// IPCheckCount 校验声明条数不超过可用记录数。
func IPCheckCount(declared, available int64) (safe bool, reason string) {
	if declared < 0 {
		return false, IPReasonNegative
	}
	if declared > available {
		return false, IPReasonCountMismatch
	}
	return true, ""
}

// IPHasReason 判定结果含某类问题。
func IPHasReason(r IPResult, reason string) bool {
	for _, x := range r.Reasons {
		if x == reason {
			return true
		}
	}
	return false
}
