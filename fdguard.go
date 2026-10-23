package main

// fdguard.go —— 文件描述符/句柄向子进程泄漏与 close-on-exec 建模。
//
// 背景：
//   启动器打开缓存、令牌、临时文件后再 spawn JVM/外部工具。若句柄未置 close-on-exec（Windows 下
//   未设 bInheritHandles 之外仍可能被显式继承），子进程会继承到敏感句柄：
//     - 子进程（或被其加载的恶意 DLL/native）可读写令牌存储、存档、锁文件；
//     - 监听套接字被继承后，即使主进程退出，端口仍被子进程占用；
//     - 管道写端泄漏导致子进程永不收到 EOF 而挂起。
//   本模块维护"打开句柄"表，标记每个句柄是否可继承，并在 spawn 前计算将被泄漏的敏感句柄；纯内存建模。

const (
	FDReasonSensitiveInherited = "fd-sensitive-handle-inheritable-before-spawn"
	FDReasonSocketInherited    = "fd-listening-socket-inherited-by-child"
	FDReasonPipeWriteLeak      = "fd-pipe-write-end-inherited-keeps-child-alive"
	FDReasonDoubleClose        = "fd-double-close-of-same-handle"
	FDReasonCloseUnknown       = "fd-close-of-untracked-handle"
)

// FDKind 句柄类别。
type FDKind int

const (
	FDKindFile FDKind = iota
	FDKindTokenStore
	FDKindListeningSocket
	FDKindPipeWrite
	FDKindLockfile
)

// FDHandle 描述一个打开句柄。
type FDHandle struct {
	ID          string
	Kind        FDKind
	Inheritable bool
	Open        bool
}

// FDTable 是句柄表。
type FDTable struct {
	handles map[string]FDHandle
}

// NewFDTable 创建句柄表。
func NewFDTable() *FDTable {
	return &FDTable{handles: map[string]FDHandle{}}
}

// FDOpen 登记一个打开句柄。
func (t *FDTable) FDOpen(h FDHandle) {
	h.Open = true
	t.handles[h.ID] = h
}

// FDClose 关闭句柄，重复/未知关闭报错。
func (t *FDTable) FDClose(id string) (ok bool, reason string) {
	h, exists := t.handles[id]
	if !exists {
		return false, FDReasonCloseUnknown
	}
	if !h.Open {
		return false, FDReasonDoubleClose
	}
	h.Open = false
	t.handles[id] = h
	return true, ""
}

// FDAuditSpawn 审计 spawn 子进程前会被继承走的句柄。
func (t *FDTable) FDAuditSpawn() (safe bool, findings []string) {
	for _, h := range t.handles {
		if !h.Open || !h.Inheritable {
			continue
		}
		switch h.Kind {
		case FDKindTokenStore, FDKindLockfile, FDKindFile:
			findings = append(findings, FDReasonSensitiveInherited+":"+h.ID)
		case FDKindListeningSocket:
			findings = append(findings, FDReasonSocketInherited+":"+h.ID)
		case FDKindPipeWrite:
			findings = append(findings, FDReasonPipeWriteLeak+":"+h.ID)
		}
	}
	return len(findings) == 0, findings
}

// FDHasFinding 判断结果是否含某前缀类别。
func FDHasFinding(findings []string, reason string) bool {
	for _, f := range findings {
		if len(f) >= len(reason) && f[:len(reason)] == reason {
			return true
		}
	}
	return false
}
