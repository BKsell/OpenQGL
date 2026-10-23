package main

// deserializeguard.go —— 不安全反序列化输入守卫。
//
// 背景：
//   启动器/整合包生态要读取多种外部数据，其中"会触发类型/类加载"的反序列化是历史重灾区：
//     - Java 原生序列化流（魔数 0xACED 0x0005，STREAM_MAGIC/STREAM_VERSION）。若把它交给
//       ObjectInputStream.readObject 且没有 ObjectInputFilter 白名单，ysoserial 一类 gadget
//       链（CommonsCollections/InvokerTransformer/Rome/Jdk7u21...）可在解析期 RCE；
//     - YAML 的 !! 全限定类型标签（!!javax.script.ScriptEngineManager、!!java.net.URL 等）
//       配合 SnakeYAML 老版本构造任意 bean；
//     - JSON 的 @type / $type 多态字段（Fastjson/Jackson default typing）指向
//       TemplatesImpl/JdbcRowSetImpl/ClassLoader 等危险类型；
//     - XML 外部对象编码（由 xmlentguard 覆盖），这里只做入口识别。
//   本模块在"决定用哪个解码器"之前识别这些高危载荷并强制走安全路径（拒绝或受限白名单解码），
//   纯字节/字符串扫描，不使用正则。

import "strings"

const (
	DZReasonJavaStreamMagic          = "dz-java-serialized-stream"
	DZReasonGadgetClass              = "dz-known-deser-gadget-class"
	DZReasonYamlTypeTag              = "dz-yaml-arbitrary-type-tag"
	DZReasonPolymorphicType          = "dz-fastjson-jackson-polymorphic-type"
	DZReasonTemplatesImpl            = "dz-templates-impl-bytecode"
	DZReasonJNDIInType               = "dz-jndi-type-reference"
	DZReasonObjectInputFilterMissing = "dz-objectinputfilter-allowlist-missing"
)

// DZPolicy 控制识别范围。
type DZPolicy struct {
	AllowJavaStreamWithAllowlist bool // 仅当调用方提供了 ObjectInputFilter 类白名单才放行
	AllowYamlArbitraryTags       bool
	AllowPolymorphicTypes        bool
}

// DZFinding 记录一处反序列化风险。
type DZFinding struct {
	Reason string
	Offset int
	Detail string
}

// DefaultDZPolicy 默认全部拒绝。
func DefaultDZPolicy() DZPolicy {
	return DZPolicy{}
}

// java 序列化流魔数 STREAM_MAGIC=0xACED, STREAM_VERSION=0x0005。
var dzJavaMagic = []byte{0xAC, 0xED, 0x00, 0x05}

// dzKnownGadgets 是常见 gadget 链/危险基类的类名片段（小写匹配）。
var dzKnownGadgets = []string{
	"org.apache.commons.collections.functors.invokertransformer",
	"org.apache.commons.collections4.functors.invokertransformer",
	"org.apache.commons.collections.keyvalue.tiedmapentry",
	"com.sun.org.apache.xalan.internal.xsltc.trax.templatesimpl",
	"com.sun.org.apache.xalan.internal.xsltc.trampoline",
	"com.sun.rowset.jdbcrowsetimpl",
	"java.beans.xmldecoder",
	"org.springframework.beans.factory.objectfactory",
	"com.mchange.v2.c3p0.wrapperdatasource",
	"org.codehaus.groovy.convertedclosure",
	"bsh.xthis",
	"javax.script.scriptenginemanager",
	"java.lang.runtime",
	"java.lang.processbuilder",
	"sun.reflect.annotation.annotationinvocationhandler",
	"org.apache.commons.beanutils.beancomparator",
}

// DZInspectBytes 检查一段待解码字节。
func DZInspectBytes(data []byte, policy DZPolicy) (safe bool, findings []DZFinding) {
	if len(data) >= 4 {
		match := true
		for i := 0; i < 4; i++ {
			if data[i] != dzJavaMagic[i] {
				match = false
				break
			}
		}
		if match {
			if !policy.AllowJavaStreamWithAllowlist {
				findings = append(findings, DZFinding{Reason: DZReasonJavaStreamMagic, Offset: 0})
			}
		}
	}

	// 在字节里以 ASCII 扫已知 gadget 类名（序列化流里类描述符常为明文 Modified UTF-8）
	low := dzToLowerASCII(data)
	for _, g := range dzKnownGadgets {
		if idx := dzIndexASCII(low, g); idx >= 0 {
			findings = append(findings, DZFinding{Reason: DZReasonGadgetClass, Offset: idx, Detail: g})
		}
	}
	if bytesContainsASCII(data, "TemplatesImpl") {
		findings = append(findings, DZFinding{Reason: DZReasonTemplatesImpl})
	}
	return len(findings) == 0, findings
}

// DZInspectYAML 检查 YAML 文本里的任意类型标签。
func DZInspectYAML(yamlText string, policy DZPolicy) (safe bool, findings []DZFinding) {
	if policy.AllowYamlArbitraryTags {
		return true, nil
	}
	// 逐行扫描 !! 与 !<url> 标签
	idx := 0
	for {
		pos := strings.Index(yamlText[idx:], "!!")
		if pos < 0 {
			break
		}
		abs := idx + pos
		tag := dzReadTypeToken(yamlText, abs+2)
		findings = append(findings, DZFinding{Reason: DZReasonYamlTypeTag, Offset: abs, Detail: tag})
		if dzDangerousType(tag) {
			findings = append(findings, DZFinding{Reason: DZReasonGadgetClass, Offset: abs, Detail: tag})
		}
		idx = abs + 2
	}
	// !<full.class.Name> 形式
	idx = 0
	for {
		pos := strings.Index(yamlText[idx:], "!<")
		if pos < 0 {
			break
		}
		abs := idx + pos
		end := strings.IndexByte(yamlText[abs:], '>')
		tag := ""
		if end > 0 {
			tag = yamlText[abs+2 : abs+end]
		}
		findings = append(findings, DZFinding{Reason: DZReasonYamlTypeTag, Offset: abs, Detail: tag})
		if dzDangerousType(tag) {
			findings = append(findings, DZFinding{Reason: DZReasonGadgetClass, Offset: abs, Detail: tag})
		}
		idx = abs + 2
	}
	return len(findings) == 0, findings
}

// DZInspectJSONObject 检查 JSON 文本里的多态类型键。
func DZInspectJSONObject(jsonText string, policy DZPolicy) (safe bool, findings []DZFinding) {
	if policy.AllowPolymorphicTypes {
		return true, nil
	}
	low := strings.ToLower(jsonText)
	for _, key := range []string{`"@type"`, `"$type"`, `"@class"`, `"_class"`} {
		searchAt := 0
		for {
			pos := strings.Index(low[searchAt:], key)
			if pos < 0 {
				break
			}
			abs := searchAt + pos
			findings = append(findings, DZFinding{Reason: DZReasonPolymorphicType, Offset: abs, Detail: key})
			searchAt = abs + len(key)
		}
	}
	// 值里出现危险类型
	for _, g := range dzKnownGadgets {
		if pos := strings.Index(low, g); pos >= 0 {
			findings = append(findings, DZFinding{Reason: DZReasonGadgetClass, Offset: pos, Detail: g})
		}
	}
	if strings.Contains(low, "ldap://") || strings.Contains(low, "rmi://") {
		findings = append(findings, DZFinding{Reason: DZReasonJNDIInType})
	}
	return len(findings) == 0, findings
}

// DZRequireObjectInputFilter 在必须读 Java 序列化流时，要求提供非空类白名单。
func DZRequireObjectInputFilter(allowedClasses []string) (safe bool, findings []DZFinding) {
	if len(allowedClasses) == 0 {
		return false, []DZFinding{{Reason: DZReasonObjectInputFilterMissing, Detail: "empty-allowlist"}}
	}
	for _, c := range allowedClasses {
		if strings.TrimSpace(c) == "" || c == "*" || strings.HasSuffix(c, ".*") {
			return false, []DZFinding{{Reason: DZReasonObjectInputFilterMissing, Detail: "wildcard-allowlist"}}
		}
	}
	return true, nil
}

func dzDangerousType(typeName string) bool {
	low := strings.ToLower(strings.TrimSpace(typeName))
	for _, g := range dzKnownGadgets {
		if strings.Contains(low, g) {
			return true
		}
	}
	dangerKeywords := []string{"classloader", "scriptengine", "process", "runtime", "jndi", "ldap", "rmi"}
	for _, k := range dangerKeywords {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

func dzReadTypeToken(s string, start int) string {
	i := start
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':' || c == '>' {
			break
		}
		i++
	}
	return s[start:i]
}

func dzToLowerASCII(data []byte) []byte {
	out := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return out
}

func dzIndexASCII(haystack []byte, needle string) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
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

func bytesContainsASCII(data []byte, token string) bool {
	return dzIndexASCII(data, token) >= 0
}
