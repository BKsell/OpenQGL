package main

// heapdumpguard.go —— JVM 故障输出路径参数守卫。
//
// 威胁模型：
//   被篡改的版本 JSON / 实例配置可以下发 -XX:HeapDumpPath=… 与
//   -XX:ErrorFile=…。这两个参数不执行命令（绕过 OnError 类命令守卫），
//   但会决定 JVM 在 OOM / 崩溃时把堆转储与致命错误日志写到哪里：
//     - 指向系统关键文件的父目录并用可预测文件名，结合符号链接可做
//       任意文件覆盖 / 占位（heap dump 体积巨大，还能直接撑爆系统盘）；
//     - 路径里塞 ../ 穿越出实例目录；
//     - 指向 Windows 设备名（NUL / CON / AUX / COM1）触发异常行为；
//     - 文件名使用环境变量展开 %APPDATA% / ${HOME}，被用来探测目录结构；
//     - HeapDumpPath 指向目录时每次崩溃生成 multi GB 文件，形成磁盘 DoS。
//
// 本模块提取这两个参数（含 = 与空格分隔两种写法），校验目标路径：
//   - 必须位于允许的实例输出根目录之内（pathguard 风格的根包含检查）；
//   - 拒绝绝对盘符 / UNC / 设备名 / 环境变量占位 / NUL 字节与控制字符；
//   - 文件名长度、目录深度有界；
//   - 纯函数，不触碰文件系统，全部判定可穷举测试。

import (
	"path/filepath"
	"strings"
)

// HeapDumpLimits 输出路径守卫的量化边界。
type HeapDumpLimits struct {
	MaxPathLen  int
	MaxDepth    int
	MaxEntries  int
}

func defaultHeapDumpLimits() HeapDumpLimits {
	return HeapDumpLimits{
		MaxPathLen: 260,
		MaxDepth:   8,
		MaxEntries: 2,
	}
}

// windowsDeviceNames 是保留设备名（任意扩展名均保留，如 NUL.txt）。
var windowsDeviceNames = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

type heapDumpEntry struct {
	Kind string // "heapdump" | "errorfile"
	Path string
	Raw  string
}

type heapDumpVerdict struct {
	OK      bool
	Reason  string
	Entries []heapDumpEntry
}

// 路径里出现这些占位说明调用方依赖运行时展开，展开结果不可静态审计。
func containsEnvPlaceholder(p string) bool {
	up := strings.ToUpper(p)
	return strings.Contains(up, "%") || strings.Contains(p, "${") || strings.Contains(p, "$(") || strings.Contains(p, "~")
}

func isWindowsDeviceSegment(seg string) bool {
	base := strings.ToUpper(seg)
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	for _, d := range windowsDeviceNames {
		if base == d {
			return true
		}
	}
	return false
}

// validateHeapDumpPath 校验输出路径相对实例根的合法性。root 为空时只做
// 语法层检查（不做根包含判定）。
func validateHeapDumpPath(p string, root string, lim HeapDumpLimits) string {
	if p == "" {
		return "empty-path"
	}
	if len(p) > lim.MaxPathLen {
		return "path-too-long"
	}
	if strings.IndexByte(p, 0) >= 0 {
		return "nul-byte"
	}
	for _, r := range p {
		if r < 32 {
			return "control-char"
		}
	}
	if containsEnvPlaceholder(p) {
		return "env-placeholder"
	}
	// 拒绝 Windows 盘符（C:）、UNC（\\server）、正斜杠 UNC 与绝对路径。
	if filepath.IsAbs(p) || strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") {
		return "absolute-path"
	}
	if len(p) >= 2 && p[1] == ':' {
		return "drive-qualified"
	}

	clean := filepath.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.Contains(clean, ".."+string(filepath.Separator)) {
		return "path-traversal"
	}

	depth := 0
	for _, seg := range strings.FieldsFunc(clean, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == "" || seg == "." {
			continue
		}
		depth++
		if isWindowsDeviceSegment(seg) {
			return "device-name"
		}
	}
	if depth > lim.MaxDepth {
		return "too-deep"
	}

	if root != "" {
		joined := filepath.Clean(filepath.Join(root, clean))
		rootClean := filepath.Clean(root)
		rel, err := filepath.Rel(rootClean, joined)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return "outside-root"
		}
	}
	return ""
}

// AuditHeapDumpArgs 从 JVM 参数中提取 HeapDumpPath / ErrorFile 并校验。
// root 是实例允许写入的输出根目录（通常为实例崩溃报告目录）。
func AuditHeapDumpArgs(args []string, root string, lim HeapDumpLimits) heapDumpVerdict {
	if lim.MaxPathLen == 0 {
		lim = defaultHeapDumpLimits()
	}
	v := heapDumpVerdict{OK: true}
	for _, arg := range args {
		var kind, prefix, value string
		lower := strings.ToLower(arg)
		switch {
		case strings.HasPrefix(lower, "-xx:heapidumppath="):
			kind, prefix = "heapdump", "-XX:HeapDumpPath="
		case strings.HasPrefix(lower, "-xx:errorfile="):
			kind, prefix = "errorfile", "-XX:ErrorFile="
		default:
			// 兼容 "-XX:HeapDumpPath path" 空格写法（极少见但 JVM 接受）。
			if strings.HasPrefix(lower, "-xx:heapidumppath ") {
				kind, value = "heapdump", strings.TrimSpace(arg[len("-XX:HeapDumpPath"):])
			} else if strings.HasPrefix(lower, "-xx:errorfile ") {
				kind, value = "errorfile", strings.TrimSpace(arg[len("-XX:ErrorFile"):])
			} else {
				continue
			}
		}
		if prefix != "" {
			value = arg[len(prefix):]
		}
		if len(v.Entries) >= lim.MaxEntries {
			v.OK = false
			v.Reason = "too-many-entries"
			return v
		}
		// 空值意味着交给 JVM 默认（工作目录下 java_pid<pid>.hprof），
		// 不指定路径时由启动器统一注入受控默认，这里标记为需调用方处理。
		if value == "" {
			continue
		}
		if reason := validateHeapDumpPath(value, root, lim); reason != "" {
			v.OK = false
			v.Reason = reason
			return v
		}
		v.Entries = append(v.Entries, heapDumpEntry{Kind: kind, Path: filepath.Clean(value), Raw: arg})
	}
	return v
}

// SummarizeHeapDumpVerdict 压成一行可读结果。
func SummarizeHeapDumpVerdict(v heapDumpVerdict) string {
	if len(v.Entries) == 0 {
		return "heapdump: none"
	}
	parts := make([]string, 0, len(v.Entries))
	for _, e := range v.Entries {
		parts = append(parts, e.Kind+"="+e.Path)
	}
	status := "ok"
	if !v.OK {
		status = "blocked:" + v.Reason
	}
	return "heapdump: " + status + " (" + strings.Join(parts, ", ") + ")"
}
