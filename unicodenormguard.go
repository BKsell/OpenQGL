package main

// unicodenormguard.go —— 文件名/标识符的 Unicode 规范化、同形与不可见字符守卫。
//
// 背景：
//   模组/世界/实例名、服务器名最终会落到文件系统或作为缓存键。Unicode 让"看起来一样"的字符串
//   有多个字节序列，由此产生一系列与 idnhomoglyph（主机名）不同的攻击面：
//     - 规范化形式不一致（NFC 与 NFD，é 可写成 U+00E9 或 e+U+0301），导致同一目录两个键、
//       白名单按一种形式匹配而磁盘按另一种形式落盘；
//     - 兼容字符：全角Ａ、连字 ﬁ、罗马数字Ⅷ、圈数字⑨、上标™ 等，视觉仿冒 "mods"、"CON"；
//     - 不可见/格式字符：零宽空格 U+200B、零宽连字 U+200C/D、BOM U+FEFF、软连字符 U+00AD、
//       双向控制 U+202A..U+202E、U+2066..U+2069（可藏扩展名与重排显示顺序）；
//     - 非规范码点：孤立代理（surrogate，UTF-8 里非法）、U+FFFD 替换符、过长编码；
//     - 同形混写 ASCII：用西里尔 а/希腊 о 仿冒拉丁 a/o 仿冒可信目录名。
//   本模块做字节级 UTF-8 解码与码点分类（自实现 UTF-8，不用 regexp/不依赖 unicode 表之外的
//   重型归一库），输出处置结论；不擅自改写用户原始名，只标记并给出去除格式字符后的建议键。

const (
	UNGReasonNotNFC           = "unicode-name-not-nfc-normalized"
	UNGReasonZeroWidth        = "unicode-name-contains-zero-width"
	UNGReasonBidiControl      = "unicode-name-contains-bidi-control"
	UNGReasonBOM              = "unicode-name-contains-bom"
	UNGReasonSoftHyphen       = "unicode-name-contains-soft-hyphen"
	UNGReasonSurrogate        = "unicode-name-contains-lone-surrogate"
	UNGReasonReplacementChar  = "unicode-name-contains-replacement-char"
	UNGReasonOverlongUTF8     = "unicode-name-overlong-utf8-sequence"
	UNGReasonContinuation     = "unicode-name-stray-continuation-byte"
	UNGReasonNonCanonical     = "unicode-name-non-canonical-code-point"
	UNGReasonConfusableScript = "unicode-name-mixed-script-confusable-with-ascii"
	UNGReasonCompatibility    = "unicode-name-compatibility-character"
)

// UNGFinding 记录一处 Unicode 名字风险。
type UNGFinding struct {
	Reason string
	Detail string
	CP     rune
}

// UNGResult 是审计结果。KeyStripped 为去掉格式/不可见字符后的建议比较键。
type UNGResult struct {
	Safe        bool
	Findings    []UNGFinding
	KeyStripped string
}

// ungDecode 是自实现的 UTF-8 解码器。返回码点序列与字节级问题（用 RuneError 标记）。
func ungDecode(s string) (runes []rune, findings []UNGFinding) {
	i := 0
	for i < len(s) {
		b0 := s[i]
		switch {
		case b0 < 0x80:
			runes = append(runes, rune(b0))
			i++
		case b0&0xE0 == 0xC0:
			if i+1 >= len(s) || s[i+1]&0xC0 != 0x80 {
				findings = append(findings, UNGFinding{Reason: UNGReasonContinuation, CP: rune(b0)})
				runes = append(runes, 0xFFFD)
				i++
				continue
			}
			cp := rune(b0&0x1F)<<6 | rune(s[i+1]&0x3F)
			if cp < 0x80 {
				findings = append(findings, UNGFinding{Reason: UNGReasonOverlongUTF8, CP: cp})
			}
			runes = append(runes, cp)
			i += 2
		case b0&0xF0 == 0xE0:
			if i+2 >= len(s) || s[i+1]&0xC0 != 0x80 || s[i+2]&0xC0 != 0x80 {
				findings = append(findings, UNGFinding{Reason: UNGReasonContinuation, CP: rune(b0)})
				runes = append(runes, 0xFFFD)
				i++
				continue
			}
			cp := rune(b0&0x0F)<<12 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F)
			if cp >= 0xD800 && cp <= 0xDFFF {
				findings = append(findings, UNGFinding{Reason: UNGReasonSurrogate, CP: cp})
			}
			if cp < 0x800 {
				findings = append(findings, UNGFinding{Reason: UNGReasonOverlongUTF8, CP: cp})
			}
			runes = append(runes, cp)
			i += 3
		case b0&0xF8 == 0xF0:
			if i+3 >= len(s) || s[i+1]&0xC0 != 0x80 || s[i+2]&0xC0 != 0x80 || s[i+3]&0xC0 != 0x80 {
				findings = append(findings, UNGFinding{Reason: UNGReasonContinuation, CP: rune(b0)})
				runes = append(runes, 0xFFFD)
				i++
				continue
			}
			cp := rune(b0&0x07)<<18 | rune(s[i+1]&0x3F)<<12 |
				rune(s[i+2]&0x3F)<<6 | rune(s[i+3]&0x3F)
			if cp < 0x10000 || cp > 0x10FFFF {
				findings = append(findings, UNGFinding{Reason: UNGReasonOverlongUTF8, CP: cp})
			}
			runes = append(runes, cp)
			i += 4
		default:
			findings = append(findings, UNGFinding{Reason: UNGReasonContinuation, CP: rune(b0)})
			runes = append(runes, 0xFFFD)
			i++
		}
	}
	return runes, findings
}

// ungIsZeroWidth/Format 判定需要剥离的不可见/格式码点。
func ungIsFormat(cp rune) bool {
	switch cp {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
		0x2066, 0x2067, 0x2068, 0x2069:
		return true
	}
	return false
}

// ungIsCompatibility 判定常见兼容/全角/圈字/连字类（精选高频，不含全表）。
func ungIsCompatibility(cp rune) bool {
	switch {
	case cp >= 0xFF01 && cp <= 0xFF5E: // 全角 ASCII
		return true
	case cp == 0xFB01 || cp == 0xFB02: // ﬁ ﬂ
		return true
	case cp >= 0x2160 && cp <= 0x217F: // 罗马数字
		return true
	case cp >= 0x2460 && cp <= 0x24FF: // 圈数字/括号数字
		return true
	case cp == 0x2122 || cp == 0x00AE || cp == 0x00A9: // TM/®/©
		return true
	}
	return false
}

// ungScriptOf 粗分码点所属脚本，用于检测混写仿冒（只列与 ASCII 易混的区段）。
func ungScriptOf(cp rune) string {
	switch {
	case cp < 0x80:
		return "ascii"
	case cp >= 0x0400 && cp <= 0x04FF:
		return "cyrillic"
	case cp >= 0x0370 && cp <= 0x03FF:
		return "greek"
	case cp >= 0x0530 && cp <= 0x058F:
		return "armenian"
	}
	return "other"
}

// UNGAudit 审计名字字符串。
func UNGAudit(name string) UNGResult {
	runes, findings := ungDecode(name)
	var stripped []rune
	asciiLike := map[string]bool{}
	hasASCIILetter := false

	for _, cp := range runes {
		switch {
		case cp == 0xFFFD:
			findings = append(findings, UNGFinding{Reason: UNGReasonReplacementChar, CP: cp})
		case cp == 0xFEFF:
			findings = append(findings, UNGFinding{Reason: UNGReasonBOM, CP: cp})
		case cp == 0x00AD:
			findings = append(findings, UNGFinding{Reason: UNGReasonSoftHyphen, CP: cp})
		case cp >= 0x202A && cp <= 0x202E || cp >= 0x2066 && cp <= 0x2069:
			findings = append(findings, UNGFinding{Reason: UNGReasonBidiControl, CP: cp})
		case cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0x2060:
			findings = append(findings, UNGFinding{Reason: UNGReasonZeroWidth, CP: cp})
		}

		if ungIsCompatibility(cp) {
			findings = append(findings, UNGFinding{Reason: UNGReasonCompatibility, CP: cp})
		}

		// 非规范码点（控制字符外的非常用格式）粗判：孤立组合符 U+0300..U+036F
		// 出现在起始或紧跟空格时通常意味着 NFD 分解。
		if cp >= 0x0300 && cp <= 0x036F {
			findings = append(findings, UNGFinding{Reason: UNGReasonNotNFC, CP: cp})
		}

		sc := ungScriptOf(cp)
		if sc != "ascii" && sc != "other" {
			asciiLike[sc] = true
		}
		isASCIILetter := (cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z')
		if isASCIILetter {
			hasASCIILetter = true
		}

		if !ungIsFormat(cp) {
			stripped = append(stripped, cp)
		}
	}

	// 与拉丁字母混排的同形脚本，且名字主体是 ASCII，判仿冒
	if hasASCIILetter {
		for sc := range asciiLike {
			findings = append(findings, UNGFinding{
				Reason: UNGReasonConfusableScript, Detail: sc})
		}
	}

	return UNGResult{
		Safe:        len(findings) == 0,
		Findings:    findings,
		KeyStripped: string(stripped),
	}
}

// UNGHasReason 判定结果是否含某类问题。
func (r UNGResult) HasReason(reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

// UNGStripFormat 仅剥离格式/不可见字符（供缓存键归一使用，不做兼容性折叠）。
func UNGStripFormat(name string) string {
	runes, _ := ungDecode(name)
	var out []rune
	for _, cp := range runes {
		if !ungIsFormat(cp) {
			out = append(out, cp)
		}
	}
	return string(out)
}
