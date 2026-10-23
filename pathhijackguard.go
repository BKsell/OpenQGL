package main

// pathhijackguard.go —— 子进程可执行文件解析劫持（PATH / unquoted path）守卫。
//
// 背景：
//   启动器会调用外部程序：java、javaw、git、7z、curl、资源下载器等。如何"找到"这个 exe 决定
//   会不会执行到攻击者预置的同名文件：
//     - exec.LookPath / CreateProcess 走 PATH 搜索，PATH 里出现空段(当前目录)、相对段、普通用户
//       可写目录，且排在真正 JDK/bin 前面，就会先加载到恶意 java.exe；
//     - Windows 未加引号且含空格的路径（C:\Program Files\...）会被逐段尝试，可在
//       C:\Program.exe 放置劫持程序；
//     - 用裸命令名（"java"）而非已解析的绝对路径，依赖环境；
//     - 当前工作目录可写且位于搜索顺序，DLL/exe 双重侧载；
//     - 找到的 exe 本身普通用户可改（被植入）。
//   本模块审查"PATH 段视图 + 一次执行请求"，纯字符串/集合判定，不使用正则。

import (
	"strings"
)

const (
	PHJReasonEmptyPathEntry   = "path-empty-entry-implies-cwd"
	PHJReasonRelativeEntry    = "path-relative-entry"
	PHJReasonWritableEntry    = "path-writable-directory-entry"
	PHJReasonCurrentDirFirst  = "path-current-directory-before-trusted"
	PHJReasonUnquotedSpaces   = "exec-unquoted-path-with-spaces"
	PHJReasonBareCommandName  = "exec-bare-command-name"
	PHJReasonResolvedWritable = "exec-resolved-binary-writable"
	PHJReasonDuplicateJava    = "path-multiple-java-bin-resolution"
)

// PHJPathEntry 描述一个 PATH 目录。
type PHJPathEntry struct {
	Path         string
	IsEmpty      bool // 空段
	IsRelative   bool
	Writable     bool
	IsCWD        bool
	ContainsJava bool
}

// PHJExecRequest 描述一次外部进程执行请求。
type PHJExecRequest struct {
	Command          string // 传入的可执行名/路径
	ResolvedAbsPath  string // LookPath 解析结果
	ResolvedWritable bool
	CWDWritable      bool
}

// PHJPolicy 设定解析策略。
type PHJPolicy struct {
	ForbidEmptyEntry      bool
	ForbidRelativeEntries bool
	RequireAbsoluteBinary bool
}

// PHJFinding 记录一处解析劫持风险。
type PHJFinding struct {
	Reason string
	Detail string
}

// DefaultPHJPolicy 默认收紧。
func DefaultPHJPolicy() PHJPolicy {
	return PHJPolicy{ForbidEmptyEntry: true, ForbidRelativeEntries: true, RequireAbsoluteBinary: true}
}

// phjIsAbsolute 判断路径是否绝对。
func phjIsAbsolute(p string) bool {
	if p == "" {
		return false
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//")
}

// PHJInspectPath 校验 PATH 段序列，trustedPrefixCount 为受信 JDK/bin 等目录之前不允许出现的风险段。
func PHJInspectPath(entries []PHJPathEntry, policy PHJPolicy) (safe bool, findings []PHJFinding) {
	javaSeen := false
	for i, e := range entries {
		if e.IsEmpty || strings.TrimSpace(e.Path) == "" {
			if policy.ForbidEmptyEntry {
				findings = append(findings, PHJFinding{Reason: PHJReasonEmptyPathEntry, Detail: itoaPHJ(i)})
			}
			continue
		}
		if e.IsCWD || (!phjIsAbsolute(e.Path) && strings.TrimSpace(e.Path) != "") {
			if e.IsCWD && i == 0 {
				findings = append(findings, PHJFinding{Reason: PHJReasonCurrentDirFirst})
			}
			if policy.ForbidRelativeEntries && !phjIsAbsolute(e.Path) {
				findings = append(findings, PHJFinding{Reason: PHJReasonRelativeEntry, Detail: e.Path})
			}
		}
		if e.Writable {
			findings = append(findings, PHJFinding{Reason: PHJReasonWritableEntry, Detail: e.Path})
		}
		if e.ContainsJava {
			if javaSeen {
				findings = append(findings, PHJFinding{Reason: PHJReasonDuplicateJava, Detail: e.Path})
			}
			javaSeen = true
		}
	}
	return len(findings) == 0, findings
}

// phjUnquotedSpaces 判断未加引号且含空格的 Windows 路径。
func phjUnquotedSpaces(cmd string) bool {
	if cmd == "" {
		return false
	}
	if strings.ContainsAny(cmd, "/\\") && strings.Contains(cmd, " ") {
		// 已经是带分隔符的路径；粗略认为调用方应加引号（由调用方传入原始命令行）
		return true
	}
	return false
}

// PHJInspectExec 校验一次外部执行请求。
func PHJInspectExec(req PHJExecRequest, cwdWritable bool, policy PHJPolicy) (safe bool, findings []PHJFinding) {
	cmd := strings.TrimSpace(req.Command)
	if !phjIsAbsolute(cmd) && !strings.ContainsAny(cmd, `/\`) {
		if policy.RequireAbsoluteBinary {
			findings = append(findings, PHJFinding{Reason: PHJReasonBareCommandName, Detail: cmd})
		}
	}
	if phjUnquotedSpaces(cmd) {
		findings = append(findings, PHJFinding{Reason: PHJReasonUnquotedSpaces, Detail: cmd})
	}
	if req.ResolvedAbsPath != "" && req.ResolvedWritable {
		findings = append(findings, PHJFinding{Reason: PHJReasonResolvedWritable, Detail: req.ResolvedAbsPath})
	}
	if cwdWritable && !phjIsAbsolute(req.ResolvedAbsPath) && strings.TrimSpace(req.ResolvedAbsPath) == "" {
		// 解析结果缺失且工作目录可写：依赖搜索顺序
		findings = append(findings, PHJFinding{Reason: PHJReasonCurrentDirFirst, Detail: "cwd-writable-unresolved"})
	}
	return len(findings) == 0, findings
}

func itoaPHJ(i int) string {
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
