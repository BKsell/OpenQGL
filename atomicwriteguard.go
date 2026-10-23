package main

// atomicwriteguard.go —— 配置/存档"临时文件 + fsync + 同目录 rename"原子落盘流程建模。
//
// 背景：
//   启动器写 accounts.json、配置、世界存档备份时，直接原地 truncate+write 会在断电/崩溃中途留下
//   半个文件（损坏且可能丢凭据）。安全做法是：同目录建临时文件 → 写完 → flush+sync 到盘 → rename
//   原子替换 → sync 父目录。常见缺陷：
//     - 临时文件建在别的目录/别的卷，rename 跨设备非原子（变成复制+删除窗口）；
//     - rename 前未 fsync，掉电仍可能得到空文件；
//     - 临时文件名可预测，被同目录其他进程抢先创建/预置（需要随机后缀 + 独占创建）；
//     - 替换后不校验最终路径，或临时文件残留；
//   纯流程步骤建模，不碰真实文件系统，不使用正则。

const (
	AWReasonTempCrossDevice = "atomicwrite-temp-file-on-different-volume"
	AWReasonTempNotInDir    = "atomicwrite-temp-file-outside-target-directory"
	AWReasonPredictableName = "atomicwrite-temp-name-predictable-or-reused"
	AWReasonMissingDataSync = "atomicwrite-rename-before-data-fsync"
	AWReasonMissingDirSync  = "atomicwrite-no-parent-directory-fsync-after-replace"
	AWReasonWrongFinalPath  = "atomicwrite-rename-destination-not-target-path"
	AWReasonTempLeftover    = "atomicwrite-temp-file-not-cleaned-up"
)

// AWStep 表示一次原子写流程中的步骤类型。
type AWStep int

const (
	AWStepCreateTemp AWStep = iota
	AWStepWrite
	AWStepFileSync
	AWStepRename
	AWStepDirSync
	AWStepCleanup
)

// AWEvent 是流程中的一步记录。
type AWEvent struct {
	Step       AWStep
	TempPath   string
	TargetDir  string
	TempVolume string
	DirVolume  string
	DestPath   string
	WantPath   string
	NameRandom bool
}

// AWAudit 校验一个完整步骤序列。
func AWAudit(evs []AWEvent) (safe bool, findings []string) {
	sawCreate, sawDataSync, sawRename, sawDirSync := false, false, false, false
	tempPath := ""
	for _, e := range evs {
		switch e.Step {
		case AWStepCreateTemp:
			sawCreate = true
			tempPath = e.TempPath
			if e.TempVolume != e.DirVolume {
				findings = append(findings, AWReasonTempCrossDevice)
			}
			if !awHasPrefix(e.TempPath, e.TargetDir) {
				findings = append(findings, AWReasonTempNotInDir)
			}
			if !e.NameRandom {
				findings = append(findings, AWReasonPredictableName)
			}
		case AWStepFileSync:
			sawDataSync = true
		case AWStepRename:
			sawRename = true
			if !sawDataSync {
				findings = append(findings, AWReasonMissingDataSync)
			}
			if e.DestPath != e.WantPath {
				findings = append(findings, AWReasonWrongFinalPath)
			}
		case AWStepDirSync:
			sawDirSync = true
		case AWStepCleanup:
			_ = tempPath
		}
	}
	if sawRename && !sawDirSync {
		findings = append(findings, AWReasonMissingDirSync)
	}
	// 若最后没有 cleanup 且临时文件与目标不同名，视为残留
	if sawCreate {
		cleaned := false
		for _, e := range evs {
			if e.Step == AWStepCleanup {
				cleaned = true
			}
		}
		// rename 已把临时文件改名，临时路径不再存在，因此 rename 成功即无残留；
		// 仅当根本没走到 rename 又没 cleanup 才报残留。
		if !cleaned && !sawRename {
			findings = append(findings, AWReasonTempLeftover)
		}
	}
	return len(findings) == 0, findings
}

func awHasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}

// AWHas 判定结果含某类问题。
func AWHas(findings []string, reason string) bool {
	for _, f := range findings {
		if f == reason {
			return true
		}
	}
	return false
}
