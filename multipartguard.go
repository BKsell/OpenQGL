package main

// multipartguard.go —— multipart/form-data 上传请求的边界、文件名与体积安全守卫。
//
// 背景：
//   启动器若带有"上传日志 / 上传世界备份 / 提交反馈附件 / 皮肤上传"能力，会构造或代理
//   multipart/form-data。风险：
//     1. 表单部件的 filename 来自外部，含 "../"、绝对路径、盘符、控制字符，若服务端或本地
//        中转按它落盘，产生路径穿越 / 覆盖；
//     2. boundary 过短、可预测或含空白 / 控制字符，可被请求走私 / 解析差异利用；
//     3. 单个部件或整个 body 超大，造成内存 / 磁盘耗尽（无流式上限）；
//     4. Content-Type 里的 charset / name 参数注入 CRLF；
//     5. 声明的 filename 与真实魔数类型不一致（伪装成图片的可执行 / HTML）。
//
// 本模块为纯逻辑裁决：给定 multipart 的元信息（boundary、各部件 filename、大小、魔数类别），
// 在"构造 / 转发请求"前给策略结论。不使用正则。

const (
	MPReasonBoundaryTooShort    = "mp-boundary-too-short"
	MPReasonBoundaryBadChars   = "mp-boundary-illegal-characters"
	MPReasonFilenameTraversal  = "mp-filename-path-traversal"
	MPReasonFilenameAbsolute   = "mp-filename-absolute-or-drive"
	MPReasonFilenameControl    = "mp-filename-control-character"
	MPReasonFilenameEmpty      = "mp-filename-empty"
	MPReasonPartTooLarge       = "mp-part-too-large"
	MPReasonBodyTooLarge       = "mp-body-too-large"
	MPReasonTooManyParts       = "mp-too-many-parts"
	MPReasonHeaderCRLF         = "mp-header-parameter-crlf"
	MPReasonFilenameTypeMismatch = "mp-filename-extension-magic-mismatch"
)

// MPPart 描述一个表单部件的安全相关元信息。
type MPPart struct {
	Name         string
	Filename     string
	Size         int64
	DeclaredKind int // 用 mimesniffguard 的 MSNKind* 表示声明类别
	MagicKind    int // 真实魔数类别
	HasMagic     bool
}

// MPPolicy 控制 multipart 校验严格度。
type MPPolicy struct {
	MinBoundaryLen  int
	MaxPartBytes    int64
	MaxBodyBytes    int64
	MaxParts        int
	CheckMagicMatch bool
}

// MPFinding 记录一处风险。
type MPFinding struct {
	Reason string
	Part   string
	Detail string
}

// DefaultMPPolicy 返回默认严格策略。
func DefaultMPPolicy() MPPolicy {
	return MPPolicy{
		MinBoundaryLen:  16,
		MaxPartBytes:    50 * 1024 * 1024,
		MaxBodyBytes:    100 * 1024 * 1024,
		MaxParts:        32,
		CheckMagicMatch: true,
	}
}

// mpBoundaryBadChar 判断 boundary 是否含非法字符（RFC 2046 bchars：不含空白与 tspecials）。
func mpBoundaryBadChar(b string) bool {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c <= 0x20 || c == 0x7f {
			return true
		}
		switch c {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=':
			return true
		}
	}
	return false
}

// mpBaseFilename 去掉路径分隔，只留文件基名（用于判断外部是否给了路径）。
func mpFilenameHasPath(filename string) bool {
	for i := 0; i < len(filename); i++ {
		if filename[i] == '/' || filename[i] == '\\' {
			return true
		}
	}
	return false
}

// mpFilenameControlChar 判断控制字符。
func mpFilenameControlChar(filename string) bool {
	for i := 0; i < len(filename); i++ {
		c := filename[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// mpFilenameIsDrive 判断 Windows 盘符 / UNC 形态基名（理论上基名不应含冒号）。
func mpFilenameIsDrive(filename string) bool {
	if len(filename) >= 2 {
		c := filename[0]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if isLetter && filename[1] == ':' {
			return true
		}
	}
	if len(filename) >= 2 && filename[0] == '\\' && filename[1] == '\\' {
		return true
	}
	return false
}

// mpHeaderHasCRLF 判断头部参数原始串是否含断行。
func mpHeaderHasCRLF(raw string) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\r' || raw[i] == '\n' {
			return true
		}
	}
	return false
}

// mpExtensionKind 根据文件扩展名给期望类别（仅覆盖上传常见类型）。
func mpExtensionKind(filename string) int {
	f := mpToLower(filename)
	// 取最后一个点后的扩展。
	dot := -1
	for i := 0; i < len(f); i++ {
		if f[i] == '.' {
			dot = i
		}
	}
	if dot < 0 {
		return MSNKindUnknown
	}
	ext := f[dot+1:]
	switch ext {
	case "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico":
		return MSNKindImage
	case "zip", "jar", "gz":
		return MSNKindArchive
	case "pdf":
		return MSNKindPDF
	case "html", "htm", "svg":
		return MSNKindHTML
	case "txt", "log", "json", "toml", "properties":
		return MSNKindText
	case "exe", "dll", "class", "elf", "bin":
		return MSNKindExecutable
	default:
		return MSNKindUnknown
	}
}

func mpToLower(s string) string {
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

// MPEvaluateRequest 校验整个 multipart 请求元信息。
func MPEvaluateRequest(boundary, rawContentType string, parts []MPPart, totalSize int64, pol MPPolicy) []MPFinding {
	var out []MPFinding
	add := func(reason, part, detail string) {
		out = append(out, MPFinding{Reason: reason, Part: part, Detail: detail})
	}
	if len(boundary) < pol.MinBoundaryLen {
		add(MPReasonBoundaryTooShort, "", "boundary")
	}
	if mpBoundaryBadChar(boundary) {
		add(MPReasonBoundaryBadChars, "", "boundary")
	}
	if rawContentType != "" && mpHeaderHasCRLF(rawContentType) {
		add(MPReasonHeaderCRLF, "", "content-type")
	}
	if len(parts) > pol.MaxParts {
		add(MPReasonTooManyParts, "", mpItoa(len(parts)))
	}
	if totalSize > pol.MaxBodyBytes {
		add(MPReasonBodyTooLarge, "", mpItoa64(totalSize))
	}
	for _, p := range parts {
		if p.Size > pol.MaxPartBytes {
			add(MPReasonPartTooLarge, p.Name, mpItoa64(p.Size))
		}
		fn := p.Filename
		if fn == "" {
			// 文件部件允许没有文件名的普通字段；这里只在声明了 filename 时检查。
		} else {
			if mpFilenameControlChar(fn) {
				add(MPReasonFilenameControl, p.Name, fn)
			}
			if mpFilenameHasPath(fn) {
				add(MPReasonFilenameTraversal, p.Name, fn)
			}
			if mpFilenameIsDrive(fn) {
				add(MPReasonFilenameAbsolute, p.Name, fn)
			}
		}
		if pol.CheckMagicMatch && p.HasMagic {
			want := mpExtensionKind(p.Filename)
			if want != MSNKindUnknown && p.MagicKind != MSNKindUnknown && want != p.MagicKind {
				add(MPReasonFilenameTypeMismatch, p.Name, p.Filename)
			}
		}
	}
	return out
}

func mpItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func mpItoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// MPIsSafe 便捷判定：常规图片上传场景。
func MPIsSafe(boundary, rawContentType string, parts []MPPart, totalSize int64) bool {
	return len(MPEvaluateRequest(boundary, rawContentType, parts, totalSize, DefaultMPPolicy())) == 0
}
