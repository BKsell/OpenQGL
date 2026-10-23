package main

// longpathguard.go —— 超长路径 / 8.3 短名 / 结尾点空格 等 Windows 文件系统陷阱守卫。
//
// 背景：
//   实例名、世界名、库路径最终拼成文件系统路径，存在一批跨平台不一致的陷阱，安全检查若只对
//   "长路径形式"做白名单，攻击者可换成另一形式绕过：
//     - 超过 MAX_PATH(260)：未加 \\?\ 前缀的 Win32 调用会失败/截断，白名单按完整路径校验、
//       实际落盘却落在截断后的另一个名字上；
//     - 8.3 短名（PROGRA~1、SECRET~1）：长名白名单匹配 "Program Files" 拦不住 "PROGRA~1"；
//     - 结尾的点或空格：Win32 会剥掉（"x.jar." 落盘成 "x.jar"），校验与落盘不一致；
//     - 路径分量为空（双斜杠）、单个/两个点分量；
//     - 路径长度计算用字节还是字符（多字节 UTF-8 中文导致字节超限但字符没超）。
//   本模块纯字符串判定，不调用文件系统，不使用正则；调用方应在校验与落盘前统一走规范化长路径。

const (
	LPReasonExceedsMaxPath   = "path-exceeds-max-path-260"
	LPReasonExceedsSafeLimit = "path-exceeds-safe-component-limit"
	LPReasonShortName83      = "path-contains-8.3-short-name"
	LPReasonTrailingDotSpace = "component-trailing-dot-or-space"
	LPReasonLeadingDotSpace  = "component-leading-space"
	LPReasonEmptyComponent   = "path-empty-component"
	LPReasonDotsComponent    = "component-is-dot-or-dotdot"
	LPReasonByteLenVsCharLen = "path-byte-length-exceeds-even-if-chars-fit"
)

const (
	LPMaxPathBytes      = 260 // 传统 Win32 MAX_PATH
	LPMaxComponentChars = 255 // 单分量安全上限（多数文件系统 255 字节）
)

// LPFinding 记录一处路径长度/命名风险。
type LPFinding struct {
	Reason string
	Index  int
	Comp   string
}

// LPAuditResult 审计结果。
type LPAuditResult struct {
	Safe       bool
	Findings   []LPFinding
	ByteLength int
	CharLength int
}

// LPAudit 审计一个已经过盘符/UNC 处理前的相对/绝对路径字符串。
func LPAudit(path string) LPAuditResult {
	comps := lpSplitComponents(path)
	var findings []LPFinding

	byteLen := len(path)
	charLen := len([]rune(path))
	if byteLen > LPMaxPathBytes {
		findings = append(findings, LPFinding{Reason: LPReasonExceedsMaxPath})
	}
	if byteLen != charLen && byteLen > LPMaxPathBytes {
		findings = append(findings, LPFinding{Reason: LPReasonByteLenVsCharLen})
	}

	for i, c := range comps {
		if c == "" {
			findings = append(findings, LPFinding{Reason: LPReasonEmptyComponent, Index: i, Comp: c})
			continue
		}
		if c == "." || c == ".." {
			findings = append(findings, LPFinding{Reason: LPReasonDotsComponent, Index: i, Comp: c})
		}
		if len([]rune(c)) > LPMaxComponentChars {
			findings = append(findings, LPFinding{Reason: LPReasonExceedsSafeLimit, Index: i, Comp: c})
		}
		last := c[len(c)-1]
		if last == '.' || last == ' ' {
			findings = append(findings, LPFinding{Reason: LPReasonTrailingDotSpace, Index: i, Comp: c})
		}
		if c[0] == ' ' {
			findings = append(findings, LPFinding{Reason: LPReasonLeadingDotSpace, Index: i, Comp: c})
		}
		if lpIs83ShortName(c) {
			findings = append(findings, LPFinding{Reason: LPReasonShortName83, Index: i, Comp: c})
		}
	}

	return LPAuditResult{
		Safe:       len(findings) == 0,
		Findings:   findings,
		ByteLength: byteLen,
		CharLength: charLen,
	}
}

// LPHasReason 判定结果含某类问题。
func (r LPAuditResult) HasReason(reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

// lpSplitComponents 按 / 与 \ 拆分，保留空分量（用于发现双分隔）。
func lpSplitComponents(p string) []string {
	var comps []string
	cur := ""
	for i := 0; i < len(p); i++ {
		if p[i] == '/' || p[i] == '\\' {
			comps = append(comps, cur)
			cur = ""
			continue
		}
		cur += string(p[i])
	}
	comps = append(comps, cur)
	// 去掉纯盘符/UNC 前缀分量（C:、空开头），但保留中间空分量用于检测
	if len(comps) > 0 && lpIsDrivePrefix(comps[0]) {
		comps = comps[1:]
	}
	return comps
}

func lpIsDrivePrefix(c string) bool {
	if len(c) == 2 && ((c[0] >= 'a' && c[0] <= 'z') ||
		(c[0] >= 'A' && c[0] <= 'Z')) && c[1] == ':' {
		return true
	}
	return c == "" // 开头分隔（\foo 或 \\?\...）由调用方另行处理
}

// lpIs83ShortName 粗判 8.3 短名：形如 NAME~N.EXT，主体 <=6 个大写字母数字、波浪号加数字。
func lpIs83ShortName(c string) bool {
	dot := -1
	for i := 0; i < len(c); i++ {
		if c[i] == '.' {
			dot = i
			break
		}
	}
	stem := c
	ext := ""
	if dot >= 0 {
		stem = c[:dot]
		ext = c[dot+1:]
	}
	tilde := -1
	for i := 0; i < len(stem); i++ {
		if stem[i] == '~' {
			tilde = i
			break
		}
	}
	if tilde < 1 {
		return false
	}
	base := stem[:tilde]
	num := stem[tilde+1:]
	if len(base) > 6 || base == "" {
		return false
	}
	for i := 0; i < len(base); i++ {
		ch := base[i]
		isUpper := ch >= 'A' && ch <= 'Z'
		isDigit := ch >= '0' && ch <= '9'
		if !isUpper && !isDigit {
			return false
		}
	}
	if num == "" {
		return false
	}
	for i := 0; i < len(num); i++ {
		if num[i] < '0' || num[i] > '9' {
			return false
		}
	}
	if len(ext) > 3 {
		return false
	}
	return true
}
