package main

// xxeguard.go —— XML DOCTYPE / 实体 / XXE（外部实体注入）与实体膨胀（Billion Laughs）
// 预扫描内核。
//
// 背景：
//   启动器目前主要消费 JSON，但服务器元数据、Maven POM、第三方整合包说明、未来可能
//   接入的 XML 配置都可能引入 XML 解析。Go 标准库 encoding/xml 默认不解析外部网络
//   实体，但内部通用实体仍会被展开，历史上存在实体递归/二次放大造成的内存与 CPU
//   拒绝服务面。为了在"把字节交给任何 XML 解码器之前"统一收口，这里做一道不依赖
//   解码器、不使用正则的纯字节静态扫描。
//
// 拦截内容：
//   1. 任意 DOCTYPE 声明（可按策略关闭，默认直接拒绝，因为业务 XML 不需要 DTD）；
//   2. 内部子集里的 <!ENTITY ...> 通用实体 / 参数实体（%name;）声明；
//   3. SYSTEM / PUBLIC 外部标识符；
//   4. http(s)://、file:、jar:、ftp:、data: 等外部 URI 引用；
//   5. 实体值里再次引用其它实体（&name;），即实体链 / 指数膨胀的原料；
//   6. 文档整体超过体积上限。
//
// 扫描器是注释 / CDATA / 处理指令感知的，避免把这些区段里的文字误判为标记。

const (
	XXEReasonDocumentTooLarge = "xxe-document-too-large"
	XXEReasonDOCTYPEPresent    = "xxe-doctype-present"
	XXEReasonEntityDeclared    = "xxe-entity-declared"
	XXEReasonParameterEntity   = "xxe-parameter-entity"
	XXEReasonExternalSystem    = "xxe-external-system-identifier"
	XXEReasonExternalPublic    = "xxe-external-public-identifier"
	XXEReasonExternalURI       = "xxe-external-uri-reference"
	XXEReasonEntityExpansion   = "xxe-entity-expansion-chain"
	XXEReasonUnterminatedMarkup = "xxe-unterminated-markup"
)

// XXEPolicy 控制 XML 预扫描严格度。
type XXEPolicy struct {
	MaxDocumentBytes  int  // 文档体积上限
	ForbidDOCTYPE     bool // 是否禁止任何 DOCTYPE
	ForbidENTITY      bool // 是否禁止 <!ENTITY> 声明
	ForbidExternalRef bool // 是否禁止 SYSTEM/PUBLIC/外部 URI
	ForbidExpansion   bool // 是否禁止实体值内再引用实体
}

// XXEFinding 记录一处可疑 XML 构造。
type XXEFinding struct {
	Reason string
	Offset int
	Detail string
}

// DefaultXXEPolicy 返回面向"不可信来源 XML"的严格默认策略。
func DefaultXXEPolicy() XXEPolicy {
	return XXEPolicy{
		MaxDocumentBytes:  4 * 1024 * 1024,
		ForbidDOCTYPE:     true,
		ForbidENTITY:      true,
		ForbidExternalRef: true,
		ForbidExpansion:   true,
	}
}

// xxeLowerASCII 把单字节归一小写。
func xxeLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// xxeHasPrefixFold 判断 data[start:] 是否以 prefix（小写 ASCII）开头，大小写不敏感。
func xxeHasPrefixFold(data []byte, start int, prefix string) bool {
	if start+len(prefix) > len(data) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if xxeLowerASCII(data[start+i]) != prefix[i] {
			return false
		}
	}
	return true
}

// xxeWordAt 判断 data[at] 处是否为完整空白/定界的关键字 word（小写 ASCII）。
func xxeWordAt(data []byte, at int, word string) bool {
	if !xxeHasPrefixFold(data, at, word) {
		return false
	}
	end := at + len(word)
	if end >= len(data) {
		return true
	}
	c := data[end]
	// 关键字后必须是空白、引号、定界符，避免 SYSTEMX 被当作 SYSTEM。
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' || c == '\'' || c == '>'
}

// xxeIsSpace 判断 XML 空白。
func xxeIsSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// xxeSkipQuoted 若 data[i] 处于引号，跳到闭合引号后一位并返回 true。
func xxeSkipQuoted(data []byte, i int) (int, bool) {
	if i >= len(data) {
		return i, false
	}
	q := data[i]
	if q != '"' && q != '\'' {
		return i, false
	}
	j := i + 1
	for j < len(data) {
		if data[j] == q {
			return j + 1, true
		}
		j++
	}
	return j, true // 引号未闭合，扫到末尾
}

// xxeFindDoctypeEnd 返回 DOCTYPE 声明结束位置（其 '>' 的下标+1），
// 正确处理内部子集的方括号与引号；找不到返回 -1。
func xxeFindDoctypeEnd(data []byte, start int) int {
	depth := 0
	i := start
	for i < len(data) {
		c := data[i]
		if c == '"' || c == '\'' {
			ni, _ := xxeSkipQuoted(data, i)
			i = ni
			continue
		}
		if c == '[' {
			depth++
			i++
			continue
		}
		if c == ']' {
			if depth > 0 {
				depth--
			}
			i++
			continue
		}
		if c == '>' && depth == 0 {
			return i + 1
		}
		i++
	}
	return -1
}

// xxeExternalSchemes 为需要拦截的外部引用 scheme（小写 ASCII）。
var xxeExternalSchemes = []string{
	"http://",
	"https://",
	"file:",
	"jar:",
	"ftp://",
	"ftps://",
	"data:",
	"gopher://",
	"netdoc:",
}

// xxeScanRegion 在 DOCTYPE 区域 [start,end) 内检查实体、外部引用与实体链。
func xxeScanRegion(data []byte, start, end int, pol XXEPolicy, findings *[]XXEFinding) {
	i := start
	for i < end {
		c := data[i]
		if c == '"' || c == '\'' {
			ni, _ := xxeSkipQuoted(data, i)
			i = ni
			continue
		}
		if c == '<' && xxeHasPrefixFold(data, i, "<!entity") {
			if pol.ForbidENTITY {
				*findings = append(*findings, XXEFinding{Reason: XXEReasonEntityDeclared, Offset: i})
			}
			if pol.ForbidExpansion {
				xxeCheckEntityValue(data, i, end, findings)
			}
			i += len("<!entity")
			continue
		}
		if c == '%' {
			// 参数实体：DOCTYPE 内出现 % 即视为参数实体用途（%name; 或 %name;）。
			if pol.ForbidENTITY {
				*findings = append(*findings, XXEFinding{Reason: XXEReasonParameterEntity, Offset: i})
			}
			i++
			continue
		}
		if pol.ForbidExternalRef {
			if xxeWordAt(data, i, "system") {
				*findings = append(*findings, XXEFinding{Reason: XXEReasonExternalSystem, Offset: i})
				i += len("system")
				continue
			}
			if xxeWordAt(data, i, "public") {
				*findings = append(*findings, XXEFinding{Reason: XXEReasonExternalPublic, Offset: i})
				i += len("public")
				continue
			}
			for _, sch := range xxeExternalSchemes {
				if xxeHasPrefixFold(data, i, sch) {
					*findings = append(*findings, XXEFinding{Reason: XXEReasonExternalURI, Offset: i, Detail: sch})
					i += len(sch)
					break
				}
			}
		}
		i++
	}
}

// xxeCheckEntityValue 检查单个 <!ENTITY ... > 的值中是否再引用实体（&name; / %name;），
// 这是实体链与指数膨胀的必要成分。
func xxeCheckEntityValue(data []byte, declStart, regionEnd int, findings *[]XXEFinding) {
	// 找到该实体声明的结束 '>'。
	depth := 0
	i := declStart
	end := -1
	for i < regionEnd {
		c := data[i]
		if c == '[' {
			depth++
		} else if c == ']' && depth > 0 {
			depth--
		} else if c == '>' && depth == 0 {
			end = i
			break
		}
		i++
	}
	if end < 0 {
		end = regionEnd
	}
	// 在引号包裹的值里找 '&' 引用。
	j := declStart
	for j < end {
		if data[j] == '"' || data[j] == '\'' {
			q := data[j]
			k := j + 1
			for k < end && data[k] != q {
				if data[k] == '&' || data[k] == '%' {
					// 排除 &#数字;/&#x十六进制; 字符引用（不构成实体链）。
					if data[k] == '&' && k+1 < end && data[k+1] == '#' {
						k++
						continue
					}
					*findings = append(*findings, XXEFinding{Reason: XXEReasonEntityExpansion, Offset: k})
					return
				}
				k++
			}
			j = k + 1
			continue
		}
		j++
	}
}

// XXEScan 对一份 XML 文档字节做安全预扫描，返回全部可疑构造。
func XXEScan(data []byte, pol XXEPolicy) []XXEFinding {
	var findings []XXEFinding
	if pol.MaxDocumentBytes > 0 && len(data) > pol.MaxDocumentBytes {
		findings = append(findings, XXEFinding{Reason: XXEReasonDocumentTooLarge, Offset: len(data)})
	}
	i := 0
	for i < len(data) {
		c := data[i]
		if c != '<' {
			i++
			continue
		}
		// 注释：<!-- ... -->
		if xxeHasPrefixFold(data, i, "<!--") {
			j := i + len("<!--")
			stop := -1
			for j+2 < len(data) {
				if data[j] == '-' && data[j+1] == '-' && data[j+2] == '>' {
					stop = j + 3
					break
				}
				j++
			}
			if stop < 0 {
				findings = append(findings, XXEFinding{Reason: XXEReasonUnterminatedMarkup, Offset: i})
				return findings
			}
			i = stop
			continue
		}
		// CDATA：<![CDATA[ ... ]]>
		if xxeHasPrefixFold(data, i, "<![cdata[") {
			j := i + len("<![cdata[")
			stop := -1
			for j+2 < len(data) {
				if data[j] == ']' && data[j+1] == ']' && data[j+2] == '>' {
					stop = j + 3
					break
				}
				j++
			}
			if stop < 0 {
				findings = append(findings, XXEFinding{Reason: XXEReasonUnterminatedMarkup, Offset: i})
				return findings
			}
			i = stop
			continue
		}
		// 处理指令：<? ... ?>
		if xxeHasPrefixFold(data, i, "<?") {
			j := i + 2
			stop := -1
			for j+1 < len(data) {
				if data[j] == '?' && data[j+1] == '>' {
					stop = j + 2
					break
				}
				j++
			}
			if stop < 0 {
				findings = append(findings, XXEFinding{Reason: XXEReasonUnterminatedMarkup, Offset: i})
				return findings
			}
			i = stop
			continue
		}
		// DOCTYPE。
		if xxeHasPrefixFold(data, i, "<!doctype") {
			if pol.ForbidDOCTYPE {
				findings = append(findings, XXEFinding{Reason: XXEReasonDOCTYPEPresent, Offset: i})
			}
			end := xxeFindDoctypeEnd(data, i+len("<!doctype"))
			if end < 0 {
				findings = append(findings, XXEFinding{Reason: XXEReasonUnterminatedMarkup, Offset: i})
				return findings
			}
			xxeScanRegion(data, i+len("<!doctype"), end, pol, &findings)
			i = end
			continue
		}
		i++
	}
	return findings
}

// XXEIsSafe 是便捷判定：默认严格策略下文档是否可安全交给 XML 解码器。
func XXEIsSafe(data []byte) bool {
	return len(XXEScan(data, DefaultXXEPolicy())) == 0
}
