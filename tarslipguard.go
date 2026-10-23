package main

// tarslipguard.go —— Tar 解包条目（tar header）路径穿越与危险条目类型守卫。
//
// 背景：
//   部分整合包 / 资源以 .tar / .tar.gz 分发。Go archive/tar 会忠实给出每个条目的 Name、
//   Typeflag、Linkname。经典的 "Tar Slip"：条目名 "../../../etc/x" 或绝对路径
//   "/etc/x"、Windows 盘符 "C:\x"，在拼接解包根目录后逃逸到目标目录之外覆盖任意文件；
//   符号链接 / 硬链接条目（TypeSymlink/TypeLink）可先在目录内放一个指向外部的链接，后续
//   普通文件条目"跟随链接"写出目录；字符/块设备、FIFO 等特殊条目在桌面解包里没有合法用途。
//
// 本模块不依赖 archive/tar，只对"已经取出的 header 字段"做纯字符校验，便于在写入前统一收口。
//
// 拦截面：
//   1. 路径穿越段 ".."、绝对 POSIX 路径、Windows 盘符 / 反斜杠穿越、UNC；
//   2. 解析后目标必须仍在解包根目录内（CleanAndJoin）；
//   3. 符号链接 / 硬链接条目默认拒绝，或其 Linkname 必须不逃逸、不指绝对路径；
//   4. 字符设备 / 块设备 / FIFO 拒绝；
//   5. Windows 保留设备名（CON、PRN、AUX、NUL、COMn、LPTn）拒绝；
//   6. 控制字符 / 空字节拒绝。

const (
	TARReasonTraversal     = "tar-parent-directory-traversal"
	TARReasonAbsolute      = "tar-absolute-path"
	TARReasonWindowsDrive  = "tar-windows-drive-letter"
	TARReasonUNC           = "tar-unc-network-path"
	TARReasonEscape        = "tar-resolved-path-outside-root"
	TARReasonSymlink       = "tar-symbolic-link-entry"
	TARReasonHardlink      = "tar-hard-link-entry"
	TARReasonLinkEscape    = "tar-link-target-escapes-root"
	TARReasonDeviceEntry   = "tar-device-or-special-entry"
	TARReasonReservedName  = "tar-windows-reserved-device-name"
	TARReasonControlByte   = "tar-control-character-in-name"
	TARReasonEmptyName     = "tar-empty-entry-name"
)

// tar header 类型标志（与 archive/tar 一致，这里自持常量避免耦合）。
const (
	tarTypeReg     = '0'
	tarTypeRegA    = '\x00'
	tarTypeLink    = '1'
	tarTypeSymlink = '2'
	tarTypeChar    = '3'
	tarTypeBlock   = '4'
	tarTypeDir     = '5'
	tarTypeFifo    = '6'
)

// TarPolicy 控制 tar 解包严格度。
type TarPolicy struct {
	ForbidSymlinks      bool // 符号链接条目直接拒绝
	ForbidHardlinks     bool // 硬链接条目直接拒绝
	ForbidSpecialFiles  bool // 字符/块设备/FIFO 拒绝
	CheckLinkTarget     bool // 即使允许链接，也要校验 Linkname 不逃逸
	ForbidAbsolute      bool
	ForbidWindowsDrive  bool
	ForbidReservedNames bool
	MaxNameBytes        int
}

// TarFinding 记录一个危险条目。
type TarFinding struct {
	Reason string
	Name   string
	Detail string
}

// TarEntry 是归档中一个条目的必要字段。
type TarEntry struct {
	Name     string
	Typeflag byte
	Linkname string
}

// DefaultTarPolicy 返回面向"不可信整合包"的严格策略。
func DefaultTarPolicy() TarPolicy {
	return TarPolicy{
		ForbidSymlinks:      true,
		ForbidHardlinks:     true,
		ForbidSpecialFiles:  true,
		CheckLinkTarget:     true,
		ForbidAbsolute:      true,
		ForbidWindowsDrive:  true,
		ForbidReservedNames: true,
		MaxNameBytes:        1024,
	}
}

// tarHasControlByte 判断是否含 NUL 及其它 C0 控制字符（允许水平制表 \t）。
func tarHasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' {
			return true
		}
		if c == 0x7f {
			return true
		}
	}
	return false
}

// tarIsDriveRelative 判断 "C:" / "C:/" / "C:\" 形态的 Windows 盘符前缀。
func tarIsDriveRelative(s string) bool {
	if len(s) < 2 {
		return false
	}
	c := s[0]
	isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	if !isLetter || s[1] != ':' {
		return false
	}
	return true
}

// tarSplitSegments 以 / 与 \ 为分隔切段，丢弃空段，把 ".." 原样保留。
func tarSplitSegments(name string) []string {
	segs := []string{}
	cur := ""
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '/' || c == '\\' {
			if cur != "" {
				segs = append(segs, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		segs = append(segs, cur)
	}
	return segs
}

// tarReservedDevice 判断段名是否为 Windows 保留设备名。
func tarReservedDevice(seg string) bool {
	if len(seg) == 0 {
		return false
	}
	upper := ""
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		upper += string(c)
	}
	switch upper {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(upper) >= 4 {
		head := upper[:3]
		num := upper[3:]
		if head == "COM" || head == "LPT" {
			allDigit := len(num) > 0
			for k := 0; k < len(num); k++ {
				if num[k] < '0' || num[k] > '9' {
					allDigit = false
					break
				}
			}
			if allDigit {
				return true
			}
		}
	}
	return false
}

// tarStem 取最后一段并去掉扩展名（纯字符，不用 filepath）。
func tarStem(name string) string {
	segs := tarSplitSegments(name)
	if len(segs) == 0 {
		return ""
	}
	last := segs[len(segs)-1]
	dot := -1
	for i := 0; i < len(last); i++ {
		if last[i] == '.' {
			dot = i
		}
	}
	if dot >= 0 {
		return last[:dot]
	}
	return last
}

// TarCleanJoin 把条目名解析为相对解包根目录的清洗路径；返回逃逸标志。
// 返回的 cleaned 一律使用 '/'，且不以 '/' 开头。
func TarCleanJoin(name string) (cleaned string, escapes bool, errReason string) {
	if name == "" {
		return "", true, TARReasonEmptyName
	}
	if tarHasControlByte(name) {
		return "", true, TARReasonControlByte
	}
	if name[0] == '/' || name[0] == '\\' {
		return "", true, TARReasonAbsolute
	}
	if tarIsDriveRelative(name) {
		return "", true, TARReasonWindowsDrive
	}
	// UNC：\\server\share（前导反斜杠已在上面归为绝对，这里再显式标注 UNC 语义）。
	if len(name) >= 2 && name[0] == '\\' && name[1] == '\\' {
		return "", true, TARReasonUNC
	}
	segs := tarSplitSegments(name)
	stack := []string{}
	for _, seg := range segs {
		if seg == "." {
			continue
		}
		if seg == ".." {
			if len(stack) == 0 {
				return "", true, TARReasonTraversal
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if tarReservedDevice(seg) {
			return "", true, TARReasonReservedName
		}
		stack = append(stack, seg)
	}
	out := ""
	for i, s := range stack {
		if i > 0 {
			out += "/"
		}
		out += s
	}
	return out, false, ""
}

// TarEvaluateEntry 校验单个 tar 条目相对解包根目录是否安全。
func TarEvaluateEntry(e TarEntry, pol TarPolicy) []TarFinding {
	var out []TarFinding
	add := func(reason, detail string) {
		out = append(out, TarFinding{Reason: reason, Name: e.Name, Detail: detail})
	}
	if pol.MaxNameBytes > 0 && len(e.Name) > pol.MaxNameBytes {
		add(TARReasonControlByte, "name-too-long")
	}
	switch e.Typeflag {
	case tarTypeChar, tarTypeBlock, tarTypeFifo:
		if pol.ForbidSpecialFiles {
			add(TARReasonDeviceEntry, "")
		}
	case tarTypeSymlink:
		if pol.ForbidSymlinks {
			add(TARReasonSymlink, "")
		}
	case tarTypeLink:
		if pol.ForbidHardlinks {
			add(TARReasonHardlink, "")
		}
	}

	// 链接目标单独校验（无论条目本身是否被类型策略拒绝）。
	if (e.Typeflag == tarTypeSymlink || e.Typeflag == tarTypeLink) && pol.CheckLinkTarget {
		if tarLinkTargetEscapes(e.Linkname) {
			add(TARReasonLinkEscape, e.Linkname)
		}
	}

	if pol.ForbidReservedNames && tarReservedDevice(tarStem(e.Name)) {
		add(TARReasonReservedName, "")
	}

	_, escapes, reason := TarCleanJoin(e.Name)
	if escapes {
		switch reason {
		case TARReasonAbsolute:
			if pol.ForbidAbsolute {
				add(reason, "")
			}
		case TARReasonWindowsDrive:
			if pol.ForbidWindowsDrive {
				add(reason, "")
			}
		default:
			add(reason, "")
		}
	}
	return out
}

// tarLinkTargetEscapes 判断链接目标是否指向根目录之外（绝对路径 / 盘符 / 含逃逸 ..）。
func tarLinkTargetEscapes(target string) bool {
	if target == "" {
		return false
	}
	if target[0] == '/' || target[0] == '\\' {
		return true
	}
	if tarIsDriveRelative(target) {
		return true
	}
	depth := 0
	for _, seg := range tarSplitSegments(target) {
		switch seg {
		case "..":
			if depth == 0 {
				return true
			}
			depth--
		case ".":
		default:
			depth++
		}
	}
	return false
}

// TarIsSafe 便捷判定。
func TarIsSafe(e TarEntry) bool {
	return len(TarEvaluateEntry(e, DefaultTarPolicy())) == 0
}
