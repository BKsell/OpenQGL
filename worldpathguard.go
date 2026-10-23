package main

// worldpathguard.go —— 世界存档目录解析与写入边界守卫。
//
// 背景：
//   启动器会备份/导入/切换 saves 下的世界。世界目录是一个"名字来自服务器/整合包、内部含 level.dat
//   与数据"的高价值目标，路径处理有独立风险面（instancenameguard 管"名字→单分量"，这里管"已解析
//   的世界目录及其内部引用"）：
//     - 目标世界目录逃逸出 saves 根（绝对路径、..、符号链接目录）；
//     - 世界内文件引用越界：level.dat / datapack / modconfig 里带的相对路径指向 saves 之外；
//     - session.lock 未被当作易变锁文件处理，备份时复制陈旧锁导致恢复后无法打开；
//     - 把 saves 根本身、或父目录当成一个"世界"整体删除/覆盖；
//     - 世界目录是符号链接/junction，备份跟随链接把链接目标（可能在库外）打包；
//     - level.dat 大小异常（0、超出上限）、缺少必备文件就当有效世界；
//     - 恢复时世界名与已有目录冲突，直接覆盖既有世界。
//   本模块对"解析后的世界路径视图"做判定，纯字符串/布尔/数值，不使用正则。

import "strings"

const (
	WPGReasonEscapesSavesRoot  = "worldpath-escapes-saves-root"
	WPGReasonAbsoluteWorld     = "worldpath-absolute-world-dir"
	WPGReasonSymlinkDir        = "worldpath-world-dir-is-symlink"
	WPGReasonInternalEscape    = "worldpath-internal-reference-escapes-world"
	WPGReasonTargetsSavesRoot  = "worldpath-target-is-saves-root-or-parent"
	WPGReasonSessionLockCopied = "worldpath-stale-session-lock-backed-up"
	WPGReasonMissingLevelDat   = "worldpath-missing-level-dat"
	WPGReasonLevelDatBadSize   = "worldpath-level-dat-size-out-of-range"
	WPGReasonOverwriteExisting = "worldpath-restore-overwrites-existing-world"
)

// WPGView 描述一个已解析的世界目录视图（路径均已转为 \ 分隔的绝对/相对形式）。
type WPGView struct {
	SavesRoot           string // 规范后的 saves 根
	WorldDir            string // 规范后的世界目录
	IsSymlink           bool
	InternalRefs        []string // 世界内元数据引用的相对路径
	BacksUpLock         bool     // 备份是否包含 session.lock
	HasLevelDat         bool
	LevelDatSize        int64
	RestoreTargetExists bool
}

// WPGPolicy 设定世界校验策略。
type WPGPolicy struct {
	MinLevelDatBytes int64
	MaxLevelDatBytes int64
}

// WPGFinding 记录一处世界路径风险。
type WPGFinding struct {
	Reason string
	Detail string
}

// DefaultWPGPolicy level.dat 8 字节（NBT 最小 gzip 头）到 64MiB。
func DefaultWPGPolicy() WPGPolicy {
	return WPGPolicy{MinLevelDatBytes: 8, MaxLevelDatBytes: 64 * 1024 * 1024}
}

// wpgNorm 统一为小写反斜杠形式做前缀比较。
func wpgNorm(p string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "/", "\\"))
}

// WPGValidateWorld 校验单个世界目录视图。
func WPGValidateWorld(v WPGView, policy WPGPolicy) (safe bool, findings []WPGFinding) {
	add := func(reason, detail string) {
		findings = append(findings, WPGFinding{Reason: reason, Detail: detail})
	}

	root := wpgNorm(v.SavesRoot)
	world := wpgNorm(v.WorldDir)

	if strings.HasPrefix(world, `\\`) || (len(world) >= 2 && world[1] == ':') {
		// 绝对盘符/UNC：只有在确实位于 saves 根下才允许，否则单独标记
		if root == "" || !strings.HasPrefix(world, wpgTrailingSep(root)) {
			add(WPGReasonAbsoluteWorld, "absolute")
		}
	}

	if root != "" {
		rootSep := wpgTrailingSep(root)
		if world != root && !strings.HasPrefix(world, rootSep) {
			add(WPGReasonEscapesSavesRoot, "not-under-root")
		}
		if world == root {
			add(WPGReasonTargetsSavesRoot, "equals-root")
		}
		// 父目录（root 去掉最后一段）也不允许成为目标
		if idx := strings.LastIndex(strings.TrimRight(root, `\`), `\`); idx > 0 {
			parent := root[:idx]
			if world == parent {
				add(WPGReasonTargetsSavesRoot, "equals-parent")
			}
		}
	}

	// 路径穿越片段
	if strings.Contains(world, "..") {
		add(WPGReasonEscapesSavesRoot, "dotdot")
	}
	if v.IsSymlink {
		add(WPGReasonSymlinkDir, "symlink")
	}

	// 世界内部引用不得越出世界目录
	for _, ref := range v.InternalRefs {
		r := wpgNorm(ref)
		if strings.Contains(r, "..") || strings.HasPrefix(r, `\\`) ||
			(len(r) >= 2 && r[1] == ':') {
			add(WPGReasonInternalEscape, ref)
		}
	}

	if v.BacksUpLock {
		add(WPGReasonSessionLockCopied, "session.lock")
	}
	if !v.HasLevelDat {
		add(WPGReasonMissingLevelDat, "level.dat")
	} else {
		if v.LevelDatSize < policy.MinLevelDatBytes ||
			v.LevelDatSize > policy.MaxLevelDatBytes {
			add(WPGReasonLevelDatBadSize, wpgItoa(v.LevelDatSize))
		}
	}
	if v.RestoreTargetExists {
		add(WPGReasonOverwriteExisting, "restore")
	}
	return len(findings) == 0, findings
}

func wpgTrailingSep(p string) string {
	p = strings.TrimRight(p, `\`)
	return p + `\`
}

func wpgItoa(i int64) string {
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
