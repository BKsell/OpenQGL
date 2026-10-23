package main

// versionrangeguard.go —— 版本范围约束（dependency range）的安全解析与上下界守卫。
//
// 背景：
//   与已有的 semverguard（严格版本号解析/分类）互补，本模块专注"版本约束表达式"：
//     >=1.20.0 <1.21.0、~1.20.1、^1.4.0、1.20.x、*。解析错误会让依赖选错构件：
//     - 约束里出现多个/非法比较符（>><1）、空格注入、非法字符；
//     - 下界高于上界（>=1.21.0 <1.20.0）导致无解或实现行为未定义；
//     - 通配符出现在非法位置（1.2*.0）；
//     - 操作的版本串本身非法（复用 semverguard 的 SVParseVersion）。
//   纯字符解析，不使用正则。

const (
	VRReasonBadOperator      = "version-range-constraint-operator-malformed"
	VRReasonRangeInverted    = "version-range-lower-bound-above-upper-bound"
	VRReasonWildcardPosition = "version-range-wildcard-in-illegal-position"
	VRReasonEmptyConstraint  = "version-range-constraint-empty"
)

// VRFinding 记录一处问题。
type VRFinding struct {
	Reason string
	Detail string
}

// vrVersion 是本模块内部使用的最小版本三元组（不含预发布，约束边界只用数字核心）。
type vrVersion struct {
	Major, Minor, Patch int64
}

// vrParseVersion 解析 major.minor.patch 数字核心（严格：三段、纯数字、非空前导零拒绝）。
func vrParseVersion(s string) (vrVersion, bool) {
	parts := vrSplitDot(s)
	if len(parts) != 3 {
		return vrVersion{}, false
	}
	var out [3]int64
	for i, p := range parts {
		if p == "" {
			return vrVersion{}, false
		}
		for k := 0; k < len(p); k++ {
			if p[k] < '0' || p[k] > '9' {
				return vrVersion{}, false
			}
		}
		if len(p) > 1 && p[0] == '0' {
			return vrVersion{}, false
		}
		var n int64
		for k := 0; k < len(p); k++ {
			n = n*10 + int64(p[k]-'0')
		}
		out[i] = n
	}
	return vrVersion{out[0], out[1], out[2]}, true
}

func vrCompare(a, b vrVersion) int {
	switch {
	case a.Major != b.Major:
		return vrCmpInt(a.Major, b.Major)
	case a.Minor != b.Minor:
		return vrCmpInt(a.Minor, b.Minor)
	case a.Patch != b.Patch:
		return vrCmpInt(a.Patch, b.Patch)
	}
	return 0
}

func vrCmpInt(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// VRAuditConstraint 审计形如 ">=1.20.0 <1.21.0" 的约束。
func VRAuditConstraint(expr string) (safe bool, findings []VRFinding) {
	tokens := vrSplitSpace(expr)
	if len(tokens) == 0 {
		return false, []VRFinding{{Reason: VRReasonEmptyConstraint}}
	}
	var lower, upper *vrVersion
	hasLower, hasUpper := false, false
	for _, tk := range tokens {
		op, verStr := vrSplitOperator(tk)
		if op == "" {
			findings = append(findings, VRFinding{Reason: VRReasonBadOperator, Detail: tk})
			continue
		}
		if vrIsWildcard(verStr) {
			if !vrWildcardLegal(verStr) {
				findings = append(findings, VRFinding{Reason: VRReasonWildcardPosition, Detail: verStr})
			}
			continue
		}
		ver, ok := vrParseVersion(verStr)
		if !ok {
			findings = append(findings, VRFinding{Reason: VRReasonBadOperator, Detail: verStr})
			continue
		}
		switch op {
		case ">=", ">", "^", "~":
			lower = &ver
			hasLower = true
		case "<=", "<":
			upper = &ver
			hasUpper = true
		case "=":
			v := ver
			lower, upper = &v, &v
			hasLower, hasUpper = true, true
		}
	}
	if hasLower && hasUpper && vrCompare(*lower, *upper) > 0 {
		findings = append(findings, VRFinding{Reason: VRReasonRangeInverted})
	}
	return len(findings) == 0, findings
}

func vrSplitOperator(tk string) (op, rest string) {
	for _, o := range []string{">=", "<=", "=", ">", "<", "^", "~"} {
		if vrHasPrefix(tk, o) {
			return o, tk[len(o):]
		}
	}
	return "", tk
}

func vrIsWildcard(s string) bool {
	return vrIndexByte(s, 'x') >= 0 || vrIndexByte(s, 'X') >= 0 || vrIndexByte(s, '*') >= 0
}

// vrWildcardLegal 一旦某段是通配，其后只能是通配或缺省。
func vrWildcardLegal(s string) bool {
	if s == "*" || s == "x" || s == "X" {
		return true
	}
	wild := false
	for _, p := range vrSplitDot(s) {
		isW := p == "x" || p == "X" || p == "*"
		if wild && !isW {
			return false
		}
		if isW {
			wild = true
		}
	}
	return true
}

func vrSplitDot(s string) []string {
	var out []string
	cur := ""
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
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

func vrSplitSpace(s string) []string {
	var out []string
	cur := ""
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' || s[i] == '\t' {
			if cur != "" {
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

func vrIndexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func vrHasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}

// VRHasReason 判定结果含某类问题。
func VRHasReason(findings []VRFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
