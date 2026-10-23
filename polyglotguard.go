package main

// polyglotguard.go —— 多态文件（polyglot）与伪装扩展名检测守卫。
//
// 背景：
//   启动器下载的资源会被不同组件按不同方式解释：图片查看器看扩展名 / Content-Type，
//   解压 / 运行链路看魔数，内嵌的 webview / 皮肤预览可能把同一文件当 HTML 渲染。攻击者
//   构造"既是图片又是 HTML / 既是 JAR 又是脚本"的多态文件，可让一个通过图片校验的文件
//   在另一环节触发 XSS、代码执行或 zip 解析歧义。典型：
//     - GIF89a/GIF87a 头后跟 HTML/JS（GIF 解析器容忍尾部垃圾，浏览器按内容嗅探成 HTML）；
//     - HTML 里塞 ZIP 的 PK 尾记录，或 ZIP 前面放脚本 shebang；
//     - PDF 头 %PDF 后嵌入 <script>，配合错误的 sniffing；
//     - 文件同时含可执行魔数 MZ/\x7fELF 与图片扩展名。
//
// 本模块对字节做纯字节扫描：在"通过魔数判定为安全类型（图片/PDF）"的文件里，查找不应出现
//   的活动内容标记（<script、javascript:、<iframe、HTML 文档结构、shebang、MZ/ELF），并支持
//   扩展名声明与魔数类别交叉校验。不使用正则。

const (
	PGReasonActiveContentInImage = "pg-active-content-inside-image"
	PGReasonActiveContentInPDF   = "pg-active-content-inside-pdf"
	PGReasonExecMagicInImage     = "pg-executable-magic-inside-image"
	PGReasonDoubleMagic          = "pg-conflicting-double-magic"
	PGReasonShebangInData        = "pg-shebang-inside-data-file"
	PGReasonHTMLSniffRisk        = "pg-html-sniffing-risk-marker"
)

// PGPolicy 控制多态检测扫描窗口与严格度。
type PGPolicy struct {
	ScanWindow         int // 对超长文件只扫描前 N 字节找活动标记，<=0 表示全文
	CheckScriptMarkers bool
	CheckExecMarkers   bool
	CheckShebang       bool
}

// PGFinding 记录一处多态命中。
type PGFinding struct {
	Reason string
	Offset int
	Detail string
}

// DefaultPGPolicy 返回默认策略（扫描前 1MiB，足以覆盖头与前置注入）。
func DefaultPGPolicy() PGPolicy {
	return PGPolicy{
		ScanWindow:         1024 * 1024,
		CheckScriptMarkers: true,
		CheckExecMarkers:   true,
		CheckShebang:       true,
	}
}

// pgLower 归一小写字节。
func pgLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// pgHasFold 在 data 的 off 处大小写不敏感匹配小写 ASCII needle。
func pgHasFold(data []byte, off int, needle string) bool {
	if off+len(needle) > len(data) {
		return false
	}
	for k := 0; k < len(needle); k++ {
		if pgLower(data[off+k]) != needle[k] {
			return false
		}
	}
	return false
}

// pgScanBytes 在窗口内收集给定标记的命中偏移（每标记只记首次）。
func pgScanMarkers(data []byte, window int, markers []string) []PGFinding {
	var out []PGFinding
	end := len(data)
	if window > 0 && end > window {
		end = window
	}
	for _, m := range markers {
		for i := 0; i+len(m) <= end; i++ {
			if pgHasFold(data, i, m) {
				out = append(out, PGFinding{Offset: i, Detail: m})
				break
			}
		}
	}
	return out
}

// pgStartsWith 判断前缀（大小写敏感，用于魔数）。
func pgStartsWith(data []byte, prefix []byte) bool {
	if len(data) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if data[i] != prefix[i] {
			return false
		}
	}
	return true
}

// pgImageMagicKind 仅判断"是否为图片魔数"。
func pgIsImageMagic(data []byte) bool {
	if pgStartsWith(data, []byte{0x89, 'P', 'N', 'G'}) {
		return true
	}
	if pgStartsWith(data, []byte{'G', 'I', 'F', '8'}) {
		return true
	}
	if len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return true
	}
	if pgStartsWith(data, []byte("BM")) {
		return true
	}
	if pgStartsWith(data, []byte("RIFF")) && len(data) >= 12 &&
		pgStartsWith(data[8:], []byte("WEBP")) {
		return true
	}
	return false
}

// PGScan 对一个已声明/魔数判为数据类（图片/PDF）的字节做活动内容与冲突魔数检测。
// declaredKind 取 mimesniffguard 的 MSNKind*；调用方通常先 MSNSniffKind 再 PGScan。
func PGScan(data []byte, declaredKind int, pol PGPolicy) []PGFinding {
	var out []PGFinding
	isImage := declaredKind == MSNKindImage
	isPDF := declaredKind == MSNKindPDF
	if !isImage && !isPDF {
		// 只对"被当作安全静态资源"的文件做多态检测。
		return out
	}

	if pol.CheckScriptMarkers {
		markers := []string{"<script", "javascript:", "<iframe", "<svg/onload", "onerror=", "<img src=x"}
		hits := pgScanMarkers(data, pol.ScanWindow, markers)
		for _, h := range hits {
			reason := PGReasonActiveContentInImage
			if isPDF {
				reason = PGReasonActiveContentInPDF
			}
			out = append(out, PGFinding{Reason: reason, Offset: h.Offset, Detail: h.Detail})
		}
		// HTML 文档结构标记单独归为 sniffing 风险。
		htmlMarkers := []string{"<!doctype html", "<html", "<body"}
		for _, h := range pgScanMarkers(data, pol.ScanWindow, htmlMarkers) {
			out = append(out, PGFinding{Reason: PGReasonHTMLSniffRisk, Offset: h.Offset, Detail: h.Detail})
		}
	}

	if pol.CheckExecMarkers {
		// MZ（PE）、\x7fELF、#!，出现在图片/PDF 数据中即高度可疑（多态或捆绑）。
		window := len(data)
		if pol.ScanWindow > 0 && window > pol.ScanWindow {
			window = pol.ScanWindow
		}
		for i := 0; i+2 <= window; i++ {
			if data[i] == 'M' && data[i+1] == 'Z' {
				out = append(out, PGFinding{Reason: PGReasonExecMagicInImage, Offset: i, Detail: "MZ"})
				break
			}
		}
		for i := 0; i+4 <= window; i++ {
			if data[i] == 0x7f && data[i+1] == 'E' && data[i+2] == 'L' && data[i+3] == 'F' {
				out = append(out, PGFinding{Reason: PGReasonExecMagicInImage, Offset: i, Detail: "ELF"})
				break
			}
		}
	}

	if pol.CheckShebang && pgStartsWith(data, []byte("#!")) {
		out = append(out, PGFinding{Reason: PGReasonShebangInData, Offset: 0, Detail: "shebang"})
	}
	return out
}

// PGDetectDoubleMagic 检测文件内同时出现两种归档/脚本冲突魔数（如 GIF 头 + PK zip）。
func PGDetectDoubleMagic(data []byte, pol PGPolicy) []PGFinding {
	var out []PGFinding
	window := len(data)
	if pol.ScanWindow > 0 && window > pol.ScanWindow {
		window = pol.ScanWindow
	}
	hasPK := false
	for i := 0; i+2 <= window; i++ {
		if data[i] == 'P' && data[i+1] == 'K' && i+4 <= window &&
			data[i+2] == 0x03 && data[i+3] == 0x04 {
			hasPK = true
			break
		}
	}
	headImage := pgIsImageMagic(data)
	if headImage && hasPK {
		out = append(out, PGFinding{Reason: PGReasonDoubleMagic, Offset: 0, Detail: "image+zip"})
	}
	return out
}

// PGIsSafe 便捷判定：图片/PDF 字节内无活动内容、无可执行魔数、无冲突双魔数。
func PGIsSafe(data []byte, declaredKind int) bool {
	pol := DefaultPGPolicy()
	if len(PGScan(data, declaredKind, pol)) != 0 {
		return false
	}
	if len(PGDetectDoubleMagic(data, pol)) != 0 {
		return false
	}
	return true
}
