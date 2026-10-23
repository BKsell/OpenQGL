package main

// nativesguard.go —— Minecraft natives 动态库目录的侧载（DLL hijacking）守卫。
//
// 背景：
//   启动器会把 LWJGL/OpenAL 等 natives（.dll/.so/.dylib）解压到一个目录，再通过
//   -Djava.library.path 或解压加载。该目录是经典的本地提权/侧载点：
//     - 目录继承了过宽权限或位于当前工作目录，其它进程可提前放入同名 DLL；
//     - 实际加载的库不在"版本清单声明的 natives 列表"里（多余/被植入 lwjgl.dll 等）；
//     - 同名库在多个来源重复（先加载到攻击者那份）；
//     - 库文件可被普通用户改写（解压后未校验完整性/权限）；
//     - 用裸名 LoadLibrary/System.loadLibrary 依赖搜索顺序，而非绝对路径。
//   本模块把"清单声明的库集合"与"磁盘实际存在的库元信息"做比对并给出目录/加载策略结论，
//   纯字符串/集合运算，不使用正则。

import (
	"path/filepath"
	"strings"
)

const (
	NTVReasonUnexpectedLibrary  = "native-unexpected-library-on-disk"
	NTVReasonMissingLibrary     = "native-declared-library-missing"
	NTVReasonDuplicateLibrary   = "native-duplicate-library-name"
	NTVReasonWritableLibrary    = "native-library-world-writable"
	NTVReasonWritableDir        = "native-dir-world-writable"
	NTVReasonBareLoadName       = "native-bare-loadlibrary-name"
	NTVReasonBadExtension       = "native-bad-library-extension"
	NTVReasonPathEscape         = "native-entry-path-escape"
	NTVReasonUnexpectedFileType = "native-unexpected-executable-type"
)

// NTVDeclaredLib 是版本清单声明的一个 native 库。
type NTVDeclaredLib struct {
	Name      string // 文件名，如 lwjgl.dll
	Size      int64
	LocalHash string // 本地用途完整性（UMFS），外部下载校验由下载链路负责
}

// NTVOnDiskLib 是磁盘上实际看到的一个库文件。
type NTVOnDiskLib struct {
	Name      string
	RelPath   string // 相对 natives 根目录
	Writable  bool
	IsSymlink bool
	LoadName  string // 如果是"加载请求"，这里是传给 LoadLibrary 的名字
	IsLoadReq bool
}

// NTVPolicy 设定 natives 目录策略。
type NTVPolicy struct {
	RequireDeclaredOnly bool // 磁盘只允许出现清单声明的库
	RequireAbsoluteLoad bool // 加载必须用绝对路径，禁止裸名
	AllowedExtensions   map[string]bool
}

// NTVFinding 记录一处 natives 风险。
type NTVFinding struct {
	Reason string
	Detail string
}

// DefaultNTVPolicy 返回默认严格策略。
func DefaultNTVPolicy() NTVPolicy {
	return NTVPolicy{
		RequireDeclaredOnly: true,
		RequireAbsoluteLoad: true,
		AllowedExtensions: map[string]bool{
			".dll": true, ".so": true, ".dylib": true, ".jnilib": true,
		},
	}
}

// ntvBase 取小写文件名。
func ntvBase(name string) string {
	name = strings.ReplaceAll(name, "/", "\\")
	if idx := strings.LastIndexByte(name, '\\'); idx >= 0 {
		name = name[idx+1:]
	}
	return strings.ToLower(name)
}

// ntvIsBareName 判断加载名是否为不含目录/盘符的裸名。
func ntvIsBareName(name string) bool {
	if name == "" {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	if len(name) >= 2 && name[1] == ':' {
		return false
	}
	return true
}

// ntvPathEscapes 判断 zip/清单条目相对路径是否逃逸出 natives 根。
func ntvPathEscapes(rel string) bool {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if strings.HasPrefix(clean, "../") || clean == ".." || filepath.IsAbs(filepath.FromSlash(rel)) {
		return true
	}
	// Windows 盘符
	if len(rel) >= 2 && rel[1] == ':' {
		return true
	}
	return false
}

// NTVInspectDir 比对清单与磁盘库集合，校验目录与文件权限。
func NTVInspectDir(declared []NTVDeclaredLib, onDisk []NTVOnDiskLib, dirWritable bool, policy NTVPolicy) (safe bool, findings []NTVFinding) {
	if dirWritable {
		findings = append(findings, NTVFinding{Reason: NTVReasonWritableDir})
	}

	declaredSet := map[string]bool{}
	for _, d := range declared {
		declaredSet[ntvBase(d.Name)] = true
	}

	seen := map[string]int{}
	for _, f := range onDisk {
		base := ntvBase(f.Name)
		seen[base]++

		if ntvPathEscapes(f.RelPath) || ntvPathEscapes(f.Name) {
			findings = append(findings, NTVFinding{Reason: NTVReasonPathEscape, Detail: f.Name})
		}
		if f.IsSymlink {
			findings = append(findings, NTVFinding{Reason: NTVReasonUnexpectedFileType, Detail: base + ":symlink"})
		}
		ext := strings.ToLower(filepath.Ext(base))
		if !policy.AllowedExtensions[ext] {
			findings = append(findings, NTVFinding{Reason: NTVReasonBadExtension, Detail: base})
		}
		if f.Writable {
			findings = append(findings, NTVFinding{Reason: NTVReasonWritableLibrary, Detail: base})
		}
		if policy.RequireDeclaredOnly && !declaredSet[base] {
			findings = append(findings, NTVFinding{Reason: NTVReasonUnexpectedLibrary, Detail: base})
		}
	}

	for name := range seen {
		if seen[name] > 1 {
			findings = append(findings, NTVFinding{Reason: NTVReasonDuplicateLibrary, Detail: name})
		}
	}
	for _, d := range declared {
		if seen[ntvBase(d.Name)] == 0 {
			findings = append(findings, NTVFinding{Reason: NTVReasonMissingLibrary, Detail: ntvBase(d.Name)})
		}
	}
	return len(findings) == 0, findings
}

// NTVInspectLoad 校验一次动态库加载请求。
func NTVInspectLoad(req NTVOnDiskLib, policy NTVPolicy) (safe bool, findings []NTVFinding) {
	name := strings.TrimSpace(req.LoadName)
	if name == "" {
		name = req.Name
	}
	if policy.RequireAbsoluteLoad && ntvIsBareName(name) {
		findings = append(findings, NTVFinding{Reason: NTVReasonBareLoadName, Detail: ntvBase(name)})
	}
	ext := strings.ToLower(filepath.Ext(name))
	if ext != "" && !policy.AllowedExtensions[ext] {
		findings = append(findings, NTVFinding{Reason: NTVReasonBadExtension, Detail: ntvBase(name)})
	}
	return len(findings) == 0, findings
}
