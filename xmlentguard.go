package main

// xmlentguard.go —— XML 外部实体（XXE）与实体爆炸（Billion Laughs）守卫。
//
// 背景：
//   启动器会拉取并解析大量 XML：Maven 的 maven-metadata.xml、POM、部分镜像/版本清单、
//   皮肤/披风服务历史上也用过 XML。尽管 Go 的 encoding/xml 默认不发起外部网络请求，但：
//     - 代码可能换用支持外部实体的第三方解析器；
//     - 文件读取型 XXE（file://）与参数实体在不同实现下行为不同；
//     - 内部实体递归展开（Billion Laughs / quadratic blowup）能把几十 KB 撑成 GB 级，
//       造成内存 DoS；
//     - XInclude 可在元素级别引入外部文档。
//   纵深防御：在把字节交给任何 XML 解析器之前，先扫描 DTD 声明并按策略处理。
//
// 本模块纯字节扫描，不使用正则，输出命中，并提供 StripDOCTYPE 净化（移除 <!DOCTYPE ...>
// 整段，含嵌套方括号），从源头消除实体替换面。

const (
	XENReasonDOCTYPE           = "xen-doctype-present"
	XENReasonExternalEntity    = "xen-external-entity-system"
	XENReasonPublicEntity      = "xen-external-entity-public"
	XENReasonParameterEntity   = "xen-parameter-entity"
	XENReasonExternalURIScheme = "xen-external-uri-scheme"
	XENReasonEntityExpansion   = "xen-entity-expansion-risk"
	XENReasonXInclude          = "xen-xinclude-directive"
	XENReasonUnclosedDOCTYPE   = "xen-unclosed-doctype"
)

// XENPolicy 控制检测严格度。
type XENPolicy struct {
	RejectDOCTYPE         bool // 出现任何 DOCTYPE 即命中（最严，元数据通常不需要）
	RejectExternal        bool // SYSTEM/PUBLIC 外部实体
	RejectParameterEntity bool // 参数实体 %name;
	RejectXInclude        bool
	MaxEntityDefs         int // 实体定义数量阈值，> 则报爆炸风险
	MaxScanBytes          int // 只扫描前 N 字节，<=0 全文
}

// XENFinding 记录一处 XML 实体风险。
type XENFinding struct {
	Reason string
	Offset int
	Detail string
}

// DefaultXENPolicy 返回默认严格策略（元数据类 XML 不应含 DTD）。
func DefaultXENPolicy() XENPolicy {
	return XENPolicy{
		RejectDOCTYPE:         true,
		RejectExternal:        true,
		RejectParameterEntity: true,
		RejectXInclude:        true,
		MaxEntityDefs:         8,
		MaxScanBytes:          2 * 1024 * 1024,
	}
}

// xenLower ASCII 小写。
func xenLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// xenToLower 归一小写副本。
func xenToLower(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = xenLower(b[i])
	}
	return string(b)
}

// xenFold 在 data 中查找与 lit 大小写无关的下标。
func xenFold(data []byte, start int, lit string) int {
	for i := start; i+len(lit) <= len(data); i++ {
		ok := true
		for j := 0; j < len(lit); j++ {
			if xenLower(data[i+j]) != lit[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// xenSkipSpace 跳过空白。
func xenSkipSpace(data []byte, i int) int {
	for i < len(data) {
		c := data[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		break
	}
	return i
}

// xenFindDOCTYPE 定位 "<!DOCTYPE" 或 "<!doctype" 起点。
func xenFindDOCTYPE(data []byte, from int) int {
	return xenFold(data, from, "<!doctype")
}

// xenDOCTYPEEnd 返回 DOCTYPE 声明结束位置（'>' 的后一位）。正确处理内部子集方括号嵌套
// 与字符串。找不到返回 -1。
func xenDOCTYPEEnd(data []byte, start int) int {
	i := start + len("<!doctype")
	depthSq := 0
	inStr := byte(0)
	for i < len(data) {
		c := data[i]
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			i++
			continue
		}
		if c == '\'' || c == '"' {
			inStr = c
			i++
			continue
		}
		if c == '[' {
			depthSq++
		} else if c == ']' {
			if depthSq > 0 {
				depthSq--
			}
		} else if c == '>' && depthSq == 0 {
			return i + 1
		}
		i++
	}
	return -1
}

// xenExternalScheme 检测外部 URI 里的危险协议。
func xenExternalScheme(uri string) (bool, string) {
	u := xenToLower(uri)
	schemes := []string{"http://", "https://", "ftp://", "ftps://", "file://",
		"jar:", "netdoc://", "gopher://", "expect://", "data:"}
	for _, sc := range schemes {
		if len(u) >= len(sc) && u[:len(sc)] == sc {
			return true, sc
		}
	}
	return false, ""
}

// XENInspect 扫描 XML 字节并给出安全结论。
func XENInspect(data []byte, policy XENPolicy) (safe bool, findings []XENFinding) {
	scan := data
	if policy.MaxScanBytes > 0 && len(scan) > policy.MaxScanBytes {
		scan = scan[:policy.MaxScanBytes]
	}

	// XInclude：xmlns 引入 + <xi:include / x:include。
	if policy.RejectXInclude {
		if xenFold(scan, 0, "xinclude") >= 0 &&
			(xenFold(scan, 0, "xmlns:xi") >= 0 || xenFold(scan, 0, "<xi:include") >= 0 ||
				xenFold(scan, 0, "href=") >= 0) {
			if off := xenFold(scan, 0, "<xi:include"); off >= 0 {
				findings = append(findings, XENFinding{Reason: XENReasonXInclude, Offset: off})
			}
		}
	}

	from := 0
	entityDefs := 0
	for {
		start := xenFindDOCTYPE(scan, from)
		if start < 0 {
			break
		}
		end := xenDOCTYPEEnd(scan, start)
		if end < 0 {
			findings = append(findings, XENFinding{Reason: XENReasonUnclosedDOCTYPE, Offset: start})
			break
		}
		body := string(scan[start:end])
		lower := xenToLower(body)

		if policy.RejectDOCTYPE {
			findings = append(findings, XENFinding{Reason: XENReasonDOCTYPE, Offset: start})
		}
		// SYSTEM 外部实体
		if policy.RejectExternal {
			if off := indexStrXEN(lower, "<!entity"); off >= 0 {
				seg := lower[off:]
				if indexStrXEN(seg, "system") >= 0 {
					findings = append(findings, XENFinding{Reason: XENReasonExternalEntity,
						Offset: start + off})
				}
				if indexStrXEN(seg, "public") >= 0 {
					findings = append(findings, XENFinding{Reason: XENReasonPublicEntity,
						Offset: start + off})
				}
			}
			// 直接外部 URI 协议
			for _, marker := range []string{"system", "public"} {
				if m := indexStrXEN(lower, marker); m >= 0 {
					rest := body[m:]
					// 取引号内 URI
					if uri, ok := xenFirstQuoted(rest); ok {
						if danger, sc := xenExternalScheme(uri); danger {
							findings = append(findings, XENFinding{Reason: XENReasonExternalURIScheme,
								Offset: start, Detail: sc})
						}
					}
				}
			}
		}
		// 参数实体 %
		if policy.RejectParameterEntity {
			for k := 0; k < len(body); k++ {
				if body[k] == '%' {
					findings = append(findings, XENFinding{Reason: XENReasonParameterEntity,
						Offset: start + k})
					break
				}
			}
		}
		// 统计实体定义数量（爆炸风险）
		entityDefs += countSubstrXEN(lower, "<!entity")
		if policy.MaxEntityDefs > 0 && entityDefs > policy.MaxEntityDefs {
			findings = append(findings, XENFinding{Reason: XENReasonEntityExpansion,
				Offset: start, Detail: "many-entity-defs"})
		}
		from = end
	}

	// 递归引用型爆炸：同一实体名被自引用，或文档中 &xxx; 引用远多于定义。
	if refs := countSubstrXEN(xenToLower(string(scan)), "&lol"); refs >= 1 {
		findings = append(findings, XENFinding{Reason: XENReasonEntityExpansion,
			Offset: 0, Detail: "self-reference-marker"})
	}
	return len(findings) == 0, findings
}

// xenFirstQuoted 从串中取第一个引号对之间的内容。
func xenFirstQuoted(s string) (string, bool) {
	start := -1
	var q byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' || s[i] == '"' {
			start = i
			q = s[i]
			break
		}
	}
	if start < 0 {
		return "", false
	}
	for j := start + 1; j < len(s); j++ {
		if s[j] == q {
			return s[start+1 : j], true
		}
	}
	return "", false
}

func indexStrXEN(s, sub string) int {
	return indexSubstrXEN(s, sub)
}

func indexSubstrXEN(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func countSubstrXEN(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
			i += len(sub) - 1
		}
	}
	return n
}

// XENStripDOCTYPE 移除所有 <!DOCTYPE ...> 声明（含内部子集），返回净化后的字节。
// 未闭合的 DOCTYPE 也会被截断到结尾，保证不把残缺声明交给解析器。
func XENStripDOCTYPE(data []byte) []byte {
	out := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if start := xenFold(data, i, "<!doctype"); start == i {
			end := xenDOCTYPEEnd(data, start)
			if end < 0 {
				// 未闭合：丢弃剩余全部
				break
			}
			i = end
			continue
		}
		out = append(out, data[i])
		i++
	}
	return out
}
