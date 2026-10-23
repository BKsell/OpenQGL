package main

// toctouguard.go —— 文件 check-then-use（TOCTOU）竞争条件守卫。
//
// 背景：
//   "先 stat/权限判断/存在性检查，再 open/exec/解压"分两步走时，两步之间文件可能被本地攻击者用
//   符号链接/硬链接替换（经典 TOCTOU）：
//     - 先 os.Stat 确认是普通文件且在安全目录，再 os.Open 写入 —— 中间被换成指向系统文件的链接；
//     - 先检查路径无穿越，再按缓存的字符串路径落盘；
//     - 校验可执行文件签名后，再 exec 旧路径（期间被覆盖）；
//     - 解压时对每个 entry 先判目标安全再创建，未用 fd/句柄级校验；
//     - 用文件是否存在决定"新建 vs 覆盖"，存在性与打开非原子。
//   正确做法：以打开后返回的 fd/句柄做 fstat，O_NOFOLLOW/RESOLVE_BENEATH、独占创建、对目录 fd 做
//   openat，校验与使用针对同一内核对象。本模块审计"检查点"和"使用点"是否共享同一不可变句柄，
//   纯布尔/字符串判定，不使用正则。

import "strings"

const (
	TCUReasonSplitStatOpen         = "toctou-stat-and-open-on-separate-steps"
	TCUReasonPathRecheckedByString = "toctou-path-revalidated-by-string-not-handle"
	TCUReasonVerifyThenExecStale   = "toctou-verify-then-exec-reopen-path"
	TCUReasonNoNoFollow            = "toctou-symlink-follow-not-disabled"
	TCUReasonZipEntryRace          = "toctou-archive-entry-check-before-create"
	TCUReasonExistThenCreate       = "toctou-existence-check-then-non-atomic-create"
	TCUReasonHandleReusedWrong     = "toctou-check-handle-differs-from-use-handle"
)

// TCUStep 描述对某个目标的一次操作。
type TCUStep struct {
	Kind          string // stat/lstat/access/open/openat/create/exec/extract/verify
	TargetPath    string
	HandleID      string // 打开后句柄标识；空表示按字符串路径
	FollowsLinks  bool
	ExclusiveFlag bool
}

// TCUFinding 记录一处 TOCTOU 风险。
type TCUFinding struct {
	Reason string
	Target string
	Detail string
}

// TCUAudit 把同一目标上的操作按时序配对审计。steps 按发生顺序排列。
func TCUAudit(steps []TCUStep) (safe bool, findings []TCUFinding) {
	// 记录每个 path 上最近一次"检查类"步骤
	lastCheck := map[string]TCUStep{}
	checkKinds := map[string]bool{"stat": true, "lstat": true, "access": true, "verify": true}

	for _, s := range steps {
		target := s.TargetPath
		switch s.Kind {
		case "stat", "lstat", "access":
			lastCheck[target] = s
		case "verify":
			lastCheck[target] = s
		case "open", "create":
			if c, ok := lastCheck[target]; ok && c.HandleID == "" && s.HandleID == "" {
				findings = append(findings, TCUFinding{
					Reason: TCUReasonSplitStatOpen, Target: target,
					Detail: c.Kind + "->open-by-path",
				})
			}
			if s.FollowsLinks {
				findings = append(findings, TCUFinding{
					Reason: TCUReasonNoNoFollow, Target: target})
			}
			if c, ok := lastCheck[target]; ok && c.Kind == "access" && !s.ExclusiveFlag {
				findings = append(findings, TCUFinding{
					Reason: TCUReasonExistThenCreate, Target: target})
			}
			lastCheck[target] = s
		case "exec":
			if c, ok := lastCheck[target]; ok {
				// 校验/检查针对的是一个句柄，exec 却按路径重新打开
				if c.HandleID != "" && s.HandleID != c.HandleID {
					findings = append(findings, TCUFinding{
						Reason: TCUReasonVerifyThenExecStale, Target: target,
						Detail: "handle-mismatch"})
				}
				if c.HandleID == "" {
					findings = append(findings, TCUFinding{
						Reason: TCUReasonVerifyThenExecStale, Target: target,
						Detail: "reopen-by-path"})
				}
			}
		case "extract":
			// 解压条目：先按字符串目标判定再创建，且未禁用链接跟随
			if s.HandleID == "" {
				findings = append(findings, TCUFinding{
					Reason: TCUReasonZipEntryRace, Target: target})
			}
			if s.FollowsLinks {
				findings = append(findings, TCUFinding{
					Reason: TCUReasonNoNoFollow, Target: target})
			}
		}
	}

	// 任何"先按路径检查、后按另一字符串路径使用"的残留模式
	for _, s := range steps {
		if checkKinds[s.Kind] && s.HandleID == "" {
			if strings.Contains(s.TargetPath, "..") {
				findings = append(findings, TCUFinding{
					Reason: TCUReasonPathRecheckedByString, Target: s.TargetPath})
			}
		}
	}
	return len(findings) == 0, findings
}
