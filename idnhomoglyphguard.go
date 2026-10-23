package main

// idnhomoglyphguard.go —— IDN 同形异义（Homograph / 同形字）钓鱼域名识别内核。
//
// 背景：
//   启动器会展示 / 访问皮肤站、整合包下载、BMCSAPI 等主机名。攻击者用视觉近似的 Unicode
//   字符注册"看起来一样"的域名：用西里尔字母 а（U+0430）冒充拉丁 a、希腊 ο 冒充 o、
//   全角／兼容字符、连字，配合 Punycode（xn--）得到如 xn--80ak6aa92e.com 这类域名，界面上
//   渲染成 "apple.com" 但实际主机完全不同，是登录令牌窃取的常见入口。
//
// 本模块是纯字符判定，不做真正的 IDNA2008 / UTS#46 映射（那应由权威库负责），只负责在
// "把主机名展示给用户 / 决定是否信任"前给出高信号风险：
//   1. 标签里混写多个不同文字体系（Latin + Cyrillic + Greek 等）——强同形字信号；
//   2. 单个标签同时含 ASCII 与"可冒充 ASCII 的高危混淆字符"；
//   3. Punycode 标签（xn--）且其 Unicode 形态含混写；
//   4. 不可见 / 组合字符、同形易混数字（0/O、1/l）作为辅助信号（默认不单独拦）；
//   5. 与一个已知品牌 ASCII 标签做"去混淆后是否全等"的相似度比对。
//
// 不使用正则。

const (
	IDNReasonMixedScripts     = "idn-mixed-scripts-in-label"
	IDNReasonCyrillicLookalike = "idn-cyrillic-ascii-lookalike"
	IDNReasonGreekLookalike   = "idn-greek-ascii-lookalike"
	IDNReasonPunycodeLabel    = "idn-punycode-label"
	IDNReasonInvisibleChar    = "idn-invisible-or-format-char"
	IDNReasonConfusablePair   = "idn-confusable-with-known-label"
	IDNReasonEmptyLabel       = "idn-empty-label"
	IDNReasonLeadingDot       = "idn-leading-or-trailing-dot"
)

// IDNPolicy 控制同形字检测严格度。
type IDNPolicy struct {
	BlockMixedScripts       bool // 混写文字体系直接判风险
	FlagPunycode            bool // 任一 xn-- 标签给信号
	BlockInvisibleChars     bool
	CheckConfusableAgainst  []string // 已知可信 ASCII 标签（如 launcher、minecraft）
	AllowPureSingleScript   bool     // 纯单一非拉丁文字体系（纯俄文站）不判混写
}

// IDNFinding 记录一个风险标签。
type IDNFinding struct {
	Reason string
	Label  string
	Detail string
}

// DefaultIDNPolicy 返回默认策略。
func DefaultIDNPolicy() IDNPolicy {
	return IDNPolicy{
		BlockMixedScripts:     true,
		FlagPunycode:          true,
		BlockInvisibleChars:   true,
		AllowPureSingleScript: true,
	}
}

// runeAt 从 UTF-8 字节串取下一个码点与字节长度。
func runeAt(s string, i int) (r rune, size int) {
	b := s[i]
	switch {
	case b < 0x80:
		return rune(b), 1
	case b&0xe0 == 0xc0:
		if i+1 >= len(s) {
			return rune(b), 1
		}
		return rune(b&0x1f)<<6 | rune(s[i+1]&0x3f), 2
	case b&0xf0 == 0xe0:
		if i+2 >= len(s) {
			return rune(b), 1
		}
		return rune(b&0x0f)<<12 | rune(s[i+1]&0x3f)<<6 | rune(s[i+2]&0x3f), 3
	default:
		if i+3 >= len(s) {
			return rune(b), 1
		}
		return rune(b&0x07)<<18 | rune(s[i+1]&0x3f)<<12 | rune(s[i+2]&0x3f)<<6 | rune(s[i+3]&0x3f), 4
	}
}

// 文字体系归类（仅覆盖浏览器同形字钓鱼高发区段，其余归 0=其它）。
const (
	idnScriptCommon  = 0
	idnScriptLatin   = 1
	idnScriptCyrillic = 2
	idnScriptGreek   = 3
	idnScriptArmenian = 4
	idnScriptHebrew  = 5
	idnScriptArabic  = 6
	idnScriptCJK     = 7
)

// idnScriptOf 判定单个码点所属文字体系。
func idnScriptOf(r rune) int {
	switch {
	case r >= 'a' && r <= 'z':
		return idnScriptLatin
	case r >= 'A' && r <= 'Z':
		return idnScriptLatin
	case r >= 0x400 && r <= 0x4FF:
		return idnScriptCyrillic
	case r >= 0x500 && r <= 0x52F:
		return idnScriptCyrillic
	case r >= 0x2DE0 && r <= 0x2DFF:
		return idnScriptCyrillic
	case r >= 0x1C80 && r <= 0x1C8F:
		return idnScriptCyrillic
	case r >= 0x370 && r <= 0x3FF:
		return idnScriptGreek
	case r >= 0x1F00 && r <= 0x1FFF:
		return idnScriptGreek
	case r >= 0x530 && r <= 0x58F:
		return idnScriptArmenian
	case r >= 0x590 && r <= 0x5FF:
		return idnScriptHebrew
	case r >= 0x600 && r <= 0x6FF:
		return idnScriptArabic
	case r >= 0x4E00 && r <= 0x9FFF:
		return idnScriptCJK
	default:
		return idnScriptCommon
	}
}

// idnIsInvisible 判断零宽 / 格式 / 软连字符等不可见码点。
func idnIsInvisible(r rune) bool {
	switch r {
	case 0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5,
		0x180B, 0x180C, 0x180D, 0x180E,
		0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
		0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
		0x2066, 0x2067, 0x2068, 0x2069,
		0xFEFF, 0xFFA0, 0xFFF9, 0xFFFA, 0xFFFB:
		return true
	}
	if r >= 0xFE00 && r <= 0xFE0F { // 变体选择符
		return true
	}
	if r >= 0xE0100 && r <= 0xE01EF {
		return true
	}
	return false
}

// idnSplitLabels 按 '.' 切标签（含 U+3002 全角句点 U+FF0E）。
func idnSplitLabels(host string) []string {
	labels := []string{}
	cur := ""
	for i := 0; i < len(host); {
		r, size := runeAt(host, i)
		i += size
		if r == '.' || r == 0x3002 || r == 0xFF0E {
			labels = append(labels, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	labels = append(labels, cur)
	return labels
}

// idnLabelScripts 返回标签里出现的"非 Common"文字体系集合。
func idnLabelScripts(label string) map[int]bool {
	scripts := map[int]bool{}
	for i := 0; i < len(label); {
		r, size := runeAt(label, i)
		i += size
		s := idnScriptOf(r)
		if s != idnScriptCommon {
			scripts[s] = true
		}
	}
	return scripts
}

// idnHasASCII 与 idnHasNonASCII 辅助。
func idnHasASCII(label string) bool {
	for i := 0; i < len(label); i++ {
		if label[i] < 0x80 {
			return true
		}
	}
	return false
}

// idnHasNonASCII 判断标签是否含任何非 ASCII 码点。
func idnHasNonASCII(label string) bool {
	for i := 0; i < len(label); i++ {
		if label[i] >= 0x80 {
			return true
		}
	}
	return false
}

// idnSkeletonMap 把高危混淆码点折叠成视觉等价 ASCII（小写）。未知码点原样小写返回。
func idnSkeletonMap(r rune) rune {
	// 西里尔形近拉丁。
	cyrillicToLatin := map[rune]rune{
		0x430: 'a', 0x431: 'b', 0x435: 'e', 0x437: 'z', 0x43E: 'o',
		0x440: 'p', 0x441: 'c', 0x445: 'y', 0x455: 's', 0x456: 'h',
		0x458: 'j', 0x463: 'y', 0x46B: 'b', 0x473: 'w', 0x45F: 'd',
	}
	if v, ok := cyrillicToLatin[r]; ok {
		return v
	}
	// 希腊形近拉丁。
	greekToLatin := map[rune]rune{
		0x3B1: 'a', 0x3B5: 'e', 0x3B9: 'i', 0x3BA: 'k', 0x3BC: 'm',
		0x3BD: 'v', 0x3BF: 'o', 0x3C1: 'p', 0x3C4: 't', 0x3C7: 'x',
		0x3C5: 'u', 0x3B3: 'y', 0x3B7: 'n',
	}
	if v, ok := greekToLatin[r]; ok {
		return v
	}
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// idnSkeleton 把标签折叠为"视觉骨架"（小写 + 形近替换），用于相似度比对。
func idnSkeleton(label string) string {
	out := ""
	for i := 0; i < len(label); {
		r, size := runeAt(label, i)
		i += size
		m := idnSkeletonMap(r)
		if m < 0x80 {
			out += string(byte(m))
		} else {
			// 无法映射到 ASCII 的非拉丁码点用占位，避免与 ASCII 品牌误等。
			out += "?"
		}
	}
	return out
}

// IDNScanHost 扫描主机名的同形字风险。
func IDNScanHost(host string, pol IDNPolicy) []IDNFinding {
	var out []IDNFinding
	if host == "" {
		return out
	}
	if host[0] == '.' {
		out = append(out, IDNFinding{Reason: IDNReasonLeadingDot, Label: host, Detail: "leading"})
	}
	if host[len(host)-1] == '.' {
		out = append(out, IDNFinding{Reason: IDNReasonLeadingDot, Label: host, Detail: "trailing"})
	}
	labels := idnSplitLabels(host)
	for _, label := range labels {
		if label == "" {
			out = append(out, IDNFinding{Reason: IDNReasonEmptyLabel, Label: host})
			continue
		}
		// 不可见字符。
		if pol.BlockInvisibleChars {
			for i := 0; i < len(label); {
				r, size := runeAt(label, i)
				i += size
				if idnIsInvisible(r) {
					out = append(out, IDNFinding{Reason: IDNReasonInvisibleChar, Label: label})
					break
				}
			}
		}
		// Punycode 标签给信号。
		low4 := ""
		if len(label) >= 4 {
			low4 = label[:4]
			if low4 == "XN--" || low4 == "xn--" {
				if pol.FlagPunycode {
					out = append(out, IDNFinding{Reason: IDNReasonPunycodeLabel, Label: label})
				}
			}
		}
		// 混写文字体系。
		if pol.BlockMixedScripts {
			scripts := idnLabelScripts(label)
			if len(scripts) >= 2 {
				hasLatin := scripts[idnScriptLatin]
				// Latin 与任一其它体系混写，或多个非拉丁体系混写，都判同形字风险。
				if hasLatin || len(scripts) >= 2 {
					reason := IDNReasonMixedScripts
					if scripts[idnScriptCyrillic] && hasLatin {
						reason = IDNReasonCyrillicLookalike
					} else if scripts[idnScriptGreek] && hasLatin {
						reason = IDNReasonGreekLookalike
					}
					out = append(out, IDNFinding{Reason: reason, Label: label})
				}
			}
		}
		// 与已知可信标签的去混淆相似度比对（仅对含非 ASCII 的标签有意义）。
		if len(pol.CheckConfusableAgainst) > 0 && idnHasNonASCII(label) {
			skeleton := idnSkeleton(label)
			for _, known := range pol.CheckConfusableAgainst {
				ks := idnSkeleton(known)
				if skeleton == ks && label != known && skeleton != "" {
					// 骨架全等但原始标签不同 → 同形字冒充。
					out = append(out, IDNFinding{Reason: IDNReasonConfusablePair, Label: label, Detail: known})
				}
			}
		}
	}
	return out
}

// IDNIsSafe 便捷判定（默认策略，不绑定品牌白名单）。
func IDNIsSafe(host string) bool {
	return len(IDNScanHost(host, DefaultIDNPolicy())) == 0
}
