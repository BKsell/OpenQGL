package main

// tempraceguard.go —— 临时文件创建 / 使用过程中的竞态与符号链接（TOCTOU）守卫。
//
// 背景：
//   启动器下载 / 解压 / 更新时会用临时目录做中转。典型不安全做法：
//     1. 用可预测名字（固定名、时间戳、进程名拼接）在共享临时目录建文件，攻击者可在同一
//        目录提前放置同名文件或指向敏感路径的符号链接，实现抢占（pre-create）与链接跟随；
//     2. 先 os.Stat 判断"文件不存在 / 是普通文件"，再 os.OpenFile/os.Create —— 两步之间
//        存在 TOCTOU 窗口，攻击者可在窗口内换成符号链接；
//     3. 用 0777 在世界可写临时目录写敏感中转文件；
//     4. 写入后再 rename 覆盖目标，但没有校验最终 fd 仍指向普通文件（O_NOFOLLOW 语义缺失）。
//
// 本模块是纯逻辑裁决：给定"临时路径名的可预测性、创建标志、目录权限、打开后再校验结果"，
// 判断该临时文件用法是否安全。它不真正建文件，只把应当由 syscall 保证的性质做成可测契约。

const (
	TRCReasonPredictableName    = "trc-predictable-temp-name"
	TRCReasonSharedWorldWritable = "trc-world-writable-temp-dir"
	TRCReasonMissingExclusive   = "trc-create-without-exclusive-flag"
	TRCReasonSymlinkFollowed    = "trc-opened-path-is-symlink"
	TRCReasonTOCTOUStatThenOpen = "trc-stat-then-open-toctou"
	TRCReasonModeTooOpen        = "trc-temp-file-mode-too-open"
	TRCReasonBadRandomEntropy   = "trc-random-suffix-too-short"
	TRCReasonNoFdRecheck        = "trc-no-post-open-type-recheck"
	TRCReasonUnsafeRenameTarget = "trc-rename-target-not-validated"
)

// TRCFileUsage 描述一次临时文件用法。
type TRCFileUsage struct {
	Path              string // 计划使用的完整路径
	NameUnpredictable bool   // 名字是否含足量随机（如 os.CreateTemp 生成的 XXXXXXXX）
	RandomSuffixLen   int    // 随机后缀长度
	InWorldWritableDir bool  // 是否位于世界可写共享目录（如 /tmp、%TEMP% 多用户场景）
	UsedExclusiveCreate bool  // 是否用 O_CREATE|O_EXCL（等价于 CreateTemp 的独占创建）
	UsedNoFollow       bool   // 是否阻止跟随符号链接（O_NOFOLLOW / 打开后 lstat 校验）
	DidStatBeforeOpen  bool   // 是否先 Stat 再 Open（危险模式）
	Mode               uint32 // 创建权限位
	RecheckedAfterOpen bool   // 打开后是否复核 fd 指向普通文件（fstat）
	RenameTargetValidated bool // rename 落地目标是否已做同设备 / 非链接校验
	WillRename         bool
}

// TRCPolicy 控制严格度。
type TRCPolicy struct {
	MinRandomSuffixLen int
	MaxTempMode        uint32
	RequireFdRecheck   bool
}

// TRCFinding 记录一处竞态风险。
type TRCFinding struct {
	Reason string
	Detail string
}

// DefaultTRCPolicy 返回默认严格策略。
func DefaultTRCPolicy() TRCPolicy {
	return TRCPolicy{
		MinRandomSuffixLen: 8,
		MaxTempMode:        0o600,
		RequireFdRecheck:   true,
	}
}

// trcHasAnyMetaChar 判断名字是否明显是"拼出来"的固定 / 半固定名（纯逻辑启发式）。
func trcLooksFixed(path string) bool {
	// 取最后一段。
	name := path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			name = path[i+1:]
			break
		}
	}
	// 全小写、不含数字、长度较短的常见固定名。
	hasDigit := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	fixed := []string{"tmp", "temp", "download", "update", "install", "partial", "cache"}
	low := trcLower(name)
	for _, f := range fixed {
		if low == f {
			return true
		}
	}
	// 名字里完全没有数字且长度 <= 8，多半不可预测。
	if !hasDigit && len(name) <= 8 {
		return true
	}
	return false
}

func trcLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// TRCEvaluate 校验一次临时文件用法。
func TRCEvaluate(u TRCFileUsage, pol TRCPolicy) []TRCFinding {
	var out []TRCFinding
	add := func(reason, detail string) {
		out = append(out, TRCFinding{Reason: reason, Detail: detail})
	}

	if !u.NameUnpredictable && trcLooksFixed(u.Path) {
		add(TRCReasonPredictableName, u.Path)
	}
	if u.NameUnpredictable && u.RandomSuffixLen < pol.MinRandomSuffixLen {
		add(TRCReasonBadRandomEntropy, "random-suffix-too-short")
	}
	if u.InWorldWritableDir && u.Mode&0o002 != 0 {
		add(TRCReasonSharedWorldWritable, "shared-temp-dir-with-world-write")
	}
	if u.InWorldWritableDir && !u.UsedExclusiveCreate {
		add(TRCReasonMissingExclusive, "shared-dir-requires-O_CREATE|O_EXCL")
	}
	if !u.UsedNoFollow {
		add(TRCReasonSymlinkFollowed, "open-may-follow-symlink")
	}
	if u.DidStatBeforeOpen {
		add(TRCReasonTOCTOUStatThenOpen, "stat-before-open-race")
	}
	if u.Mode != 0 && u.Mode&0o777&^pol.MaxTempMode != 0 {
		add(TRCReasonModeTooOpen, "temp-file-mode-exceeds-0600")
	}
	if pol.RequireFdRecheck && !u.RecheckedAfterOpen {
		add(TRCReasonNoFdRecheck, "must-fstat-fd-after-open")
	}
	if u.WillRename && !u.RenameTargetValidated {
		add(TRCReasonUnsafeRenameTarget, "rename-target-unvalidated")
	}
	return out
}

// TRCSafeUsage 构造一份"安全用法"模板，便于调用方对照（CreateTemp 语义）。
func TRCSafeUsage(path string) TRCFileUsage {
	return TRCFileUsage{
		Path:                  path,
		NameUnpredictable:     true,
		RandomSuffixLen:       10,
		InWorldWritableDir:    true,
		UsedExclusiveCreate:   true,
		UsedNoFollow:          true,
		DidStatBeforeOpen:     false,
		Mode:                  0o600,
		RecheckedAfterOpen:    true,
		WillRename:            false,
		RenameTargetValidated: true,
	}
}

// TRCIsSafe 便捷判定。
func TRCIsSafe(u TRCFileUsage) bool {
	return len(TRCEvaluate(u, DefaultTRCPolicy())) == 0
}
