package main

// mimesniffguard.go —— 下载内容的声明类型 / 真实魔数（magic bytes）一致性与 MIME 混淆守卫。
//
// 背景：
//   启动器会下载 jar、整合包、png 皮肤、可执行的 Java 运行时等。浏览器 / 桌面历史上长期
//   做"内容嗅探"：当 Content-Type 缺失、不准或是通用类型（application/octet-stream、
//   text/plain）时，按文件头字节猜测真实类型。攻击者把可执行 / HTML / 脚本伪装成图片或
//   文本下发，若上层又按嗅探结果决定"直接打开 / 内嵌渲染"，就会得到 XSS 或意外执行。
//
// 本模块做纯字节判定：
//   1. 用 WHATFO 嗅探标准里的高信号魔数签名识别真实类型（PNG/JPEG/GIF/WEBP/ZIP/JAR/GZ/
//      PDF/ELF/PE/HTML/SVG/脚本/BMP/ICO/class）；
//   2. 比对服务器声明 Content-Type 与真实魔数是否同"安全类别"；
//   3. 声明为 image/* 但魔数是 HTML / 脚本 / 可执行 → 高危混淆；
//   4. 提供"是否必须 nosniff、是否允许内嵌打开"的决策。
//
// 不使用正则。

const (
	MSNReasonDeclaredExecutable     = "msn-declared-executable"
	MSNReasonMagicExecutable        = "msn-magic-executable"
	MSNReasonImageIsHTML            = "msn-image-declared-but-html-magic"
	MSNReasonImageIsScript          = "msn-image-declared-but-script-magic"
	MSNReasonMimeTypeMismatch       = "msn-declared-type-magic-mismatch"
	MSNReasonSVGScriptCarrier       = "msn-svg-may-carry-script"
	MSNReasonHTMLInlineRisk         = "msn-html-inline-render-risk"
	MSNReasonUnknownBinary          = "msn-unknown-binary"
	MSNReasonEmptyBody              = "msn-empty-body"
)

// 真实内容类别。
const (
	MSNKindUnknown = iota
	MSNKindImage
	MSNKindArchive // zip/jar/gz
	MSNKindHTML
	MSNKindScript
	MSNKindExecutable // elf/pe/class/bat 引导
	MSNKindPDF
	MSNKindText
)

// MSNPolicy 控制嗅探严格度。
type MSNPolicy struct {
	TrustDeclaredType     bool // 声明类型准确时是否直接采信
	BlockExecutableMagic  bool // 魔数为可执行时拦截
	ForbidInlineUntrusted bool // 非归档/图片禁止内嵌渲染
	RequireNosniffForHTML bool // HTML 必须带 nosniff 才允许内嵌
	MaxSniffBytes         int
}

// MSNFinding 记录一处类型风险。
type MSNFinding struct {
	Reason       string
	DeclaredType string
	DetectedKind int
	Detail       string
}

// DefaultMSNPolicy 返回默认严格策略。
func DefaultMSNPolicy() MSNPolicy {
	return MSNPolicy{
		TrustDeclaredType:     true,
		BlockExecutableMagic:  true,
		ForbidInlineUntrusted: true,
		RequireNosniffForHTML: true,
		MaxSniffBytes:         512,
	}
}

// msnHasPrefix 判断 b 是否以 sig 开头。
func msnHasPrefix(b []byte, sig []byte) bool {
	if len(b) < len(sig) {
		return false
	}
	for i := 0; i < len(sig); i++ {
		if b[i] != sig[i] {
			return false
		}
	}
	return false
}

// msnLowerASCII 归一小写。
func msnLowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// msnTrimSpace 去首尾空白。
func msnTrimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

// MSNSniffKind 依据文件头魔数返回真实类别。
func MSNSniffKind(body []byte) int {
	if len(body) == 0 {
		return MSNKindUnknown
	}
	switch {
	case msnHasPrefix(body, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return MSNKindImage // PNG
	case msnHasPrefix(body, []byte{0xFF, 0xD8, 0xFF}):
		return MSNKindImage // JPEG
	case msnHasPrefix(body, []byte("GIF87a")) || msnHasPrefix(body, []byte("GIF89a")):
		return MSNKindImage // GIF
	case msnHasPrefix(body, []byte("RIFF")) && len(body) > 11 &&
		msnHasPrefix(body[8:], []byte("WEBP")):
		return MSNKindImage // WEBP
	case msnHasPrefix(body, []byte("BM")):
		return MSNKindImage // BMP
	case msnHasPrefix(body, []byte{0x00, 0x00, 0x01, 0x00}):
		return MSNKindImage // ICO
	case msnHasPrefix(body, []byte("PK\x03\x04")) || msnHasPrefix(body, []byte("PK\x05\x06")):
		return MSNKindArchive // ZIP/JAR
	case msnHasPrefix(body, []byte{0x1F, 0x8B}):
		return MSNKindArchive // GZIP
	case msnHasPrefix(body, []byte("%PDF-")):
		return MSNKindPDF
	case msnHasPrefix(body, []byte{0x7F, 'E', 'L', 'F'}):
		return MSNKindExecutable // ELF
	case msnHasPrefix(body, []byte("MZ")):
		return MSNKindExecutable // PE / DOS
	}
	// Java class：CA FE BA BE。
	if len(body) >= 4 && body[0] == 0xCA && body[1] == 0xFE && body[2] == 0xBA && body[3] == 0xBE {
		return MSNKindExecutable
	}
	// 文本类：跳过前导空白/BOM 后识别 HTML / SVG / 脚本引导。
	head := msnTextHead(body)
	if msnStartsWithFold(head, "<!doctype html") || msnStartsWithFold(head, "<html") ||
		msnStartsWithFold(head, "<!--") || msnStartsWithFold(head, "<head") ||
		msnStartsWithFold(head, "<script") {
		return MSNKindHTML
	}
	if msnStartsWithFold(head, "<?xml") || msnStartsWithFold(head, "<svg") {
		// SVG 是可携带 <script> 的 XML，按 HTML 类高风险载体处理。
		return MSNKindHTML
	}
	if msnLooksLikeScript(head) {
		return MSNKindScript
	}
	if msnIsMostlyText(body) {
		return MSNKindText
	}
	return MSNKindUnknown
}

// msnTextHead 跳过 UTF BOM 与空白，返回前若干字节字符串。
func msnTextHead(body []byte) string {
	i := 0
	if msnHasPrefix(body, []byte{0xEF, 0xBB, 0xBF}) {
		i = 3
	}
	for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n') {
		i++
	}
	end := i + 64
	if end > len(body) {
		end = len(body)
	}
	return string(body[i:end])
}

// msnStartsWithFold 大小写不敏感前缀。
func msnStartsWithFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if msnLowerASCII(s[i]) != prefix[i] {
			return false
		}
	}
	return true
}

// msnLooksLikeScript 识别常见脚本 shebang / 引导。
func msnLooksLikeScript(head string) bool {
	prefixes := []string{"#!", "function(", "var ", "const ", "let ", "import ", "#!/bin/sh", "@echo off"}
	for _, p := range prefixes {
		if msnStartsWithFold(head, p) {
			return true
		}
	}
	return false
}

// msnIsMostlyText 判断主体是否基本为可打印文本（用于归类 text）。
func msnIsMostlyText(body []byte) bool {
	limit := len(body)
	if limit > 256 {
		limit = 256
	}
	printable := 0
	for i := 0; i < limit; i++ {
		c := body[i]
		if c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c < 0x7F) || c >= 0x80 {
			printable++
		}
	}
	return limit > 0 && printable*100/limit >= 90
}

// msnDeclaredKind 把声明 Content-Type 粗略归类。
func msnDeclaredKind(declared string) int {
	d := msnLowerMIME(declared)
	// 去掉 ;charset=... 参数。
	if sc := msnIndexSemicolon(d); sc >= 0 {
		d = d[:sc]
	}
	d = msnTrimSpace(d)
	switch {
	case msnHasPrefixStr(d, "image/"):
		return MSNKindImage
	case d == "text/html" || d == "application/xhtml+xml":
		return MSNKindHTML
	case d == "image/svg+xml":
		return MSNKindHTML
	case msnHasPrefixStr(d, "text/") || d == "application/javascript":
		return MSNKindText
	case d == "application/zip" || d == "application/java-archive" ||
		msnHasPrefixStr(d, "application/x-gzip") || d == "application/gzip" ||
		msnHasPrefixStr(d, "application/x-jar"):
		return MSNKindArchive
	case d == "application/pdf":
		return MSNKindPDF
	case msnHasPrefixStr(d, "application/x-msdownload") || d == "application/x-executable" ||
		msnHasPrefixStr(d, "application/x-dosexec"):
		return MSNKindExecutable
	case d == "application/octet-stream" || d == "":
		return MSNKindUnknown
	default:
		return MSNKindUnknown
	}
}

// msnLowerMIME 返回小写副本（仅 ASCII）。
func msnLowerMIME(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = msnLowerASCII(s[i])
	}
	return string(b)
}

func msnIndexSemicolon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			return i
		}
	}
	return -1
}

func msnHasPrefixStr(s, p string) bool {
	if len(s) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if s[i] != p[i] {
			return false
		}
	}
	return true
}

// MSNEvaluate 比对声明类型与真实魔数。
func MSNEvaluate(declaredType string, body []byte, hasNosniff bool, pol MSNPolicy) []MSNFinding {
	var out []MSNFinding
	if len(body) == 0 {
		out = append(out, MSNFinding{Reason: MSNReasonEmptyBody, DeclaredType: declaredType, DetectedKind: MSNKindUnknown})
		return out
	}
	detected := MSNSniffKind(body)
	declaredKind := msnDeclaredKind(declaredType)

	if pol.BlockExecutableMagic && detected == MSNKindExecutable {
		out = append(out, MSNFinding{Reason: MSNReasonMagicExecutable, DeclaredType: declaredType, DetectedKind: detected})
	}
	if declaredKind == MSNKindExecutable {
		out = append(out, MSNFinding{Reason: MSNReasonDeclaredExecutable, DeclaredType: declaredType, DetectedKind: detected})
	}

	// 声明图片，真实却是 HTML/脚本/可执行：经典伪装。
	if declaredKind == MSNKindImage {
		switch detected {
		case MSNKindHTML:
			out = append(out, MSNFinding{Reason: MSNReasonImageIsHTML, DeclaredType: declaredType, DetectedKind: detected})
		case MSNKindScript:
			out = append(out, MSNFinding{Reason: MSNReasonImageIsScript, DeclaredType: declaredType, DetectedKind: detected})
		case MSNKindExecutable:
			out = append(out, MSNFinding{Reason: MSNReasonImageIsScript, DeclaredType: declaredType, DetectedKind: detected, Detail: "executable"})
		}
	}

	// 声明与魔数类别不一致（且双方都明确、非 unknown）即给信号。
	if pol.TrustDeclaredType && declaredKind != MSNKindUnknown &&
		detected != MSNKindUnknown && declaredKind != detected {
		out = append(out, MSNFinding{Reason: MSNReasonMimeTypeMismatch, DeclaredType: declaredType, DetectedKind: detected})
	}

	// SVG / HTML 内嵌渲染风险。
	if detected == MSNKindHTML {
		if !pol.RequireNosniffForHTML || hasNosniff {
			// 即便带 nosniff，SVG 仍可携带脚本，单独标注。
			if msnStartsWithFold(msnTextHead(body), "<?xml") || msnStartsWithFold(msnTextHead(body), "<svg") {
				out = append(out, MSNFinding{Reason: MSNReasonSVGScriptCarrier, DeclaredType: declaredType, DetectedKind: detected})
			}
		}
		if pol.ForbidInlineUntrusted {
			out = append(out, MSNFinding{Reason: MSNReasonHTMLInlineRisk, DeclaredType: declaredType, DetectedKind: detected})
		}
	}

	if detected == MSNKindUnknown && declaredKind == MSNKindUnknown {
		out = append(out, MSNFinding{Reason: MSNReasonUnknownBinary, DeclaredType: declaredType, DetectedKind: detected})
	}
	return out
}

// MSNIsSafe 便捷判定：下载内容是否可按声明类型安全处理。
func MSNIsSafe(declaredType string, body []byte, hasNosniff bool) bool {
	return len(MSNEvaluate(declaredType, body, hasNosniff, DefaultMSNPolicy())) == 0
}
