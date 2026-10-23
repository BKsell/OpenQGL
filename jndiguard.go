package main

// jndiguard.go —— 不可信文本中的 JNDI 查找注入（Log4Shell 类）守卫。
//
// 背景：
//   Log4Shell（CVE-2021-44228）的根因是日志/消息里的 ${jndi:ldap://host/a} 被日志库当作
//   查找表达式二次解析，进而发起 LDAP/RMI/DNS 出站并加载远端类。启动器会把大量"服务器可控"
//   字符串带进本地处理：聊天、MOTD、服务器名、版本号、玩家名、异常消息、资源包描述、MOTD 图标
//   的 URL 等。任何一处被原样写进基于 log4j2 的组件（或转发到带该漏洞的旧版 JVM 日志），
//   都可能触发。
//
// 本模块对任意不可信文本做纯字节扫描，识别：
//   - ${jndi: 与各种大小写、嵌套 ${${::-j}${::-n}...}、全角/空白混淆；
//   - ${...} 里的危险协议：ldap/ldaps/rmi/dns/iiop/iiopname/corba/naming；
//   - 其它高风险查找：${hostName}、${env:..}、${sys:..}、${java:..}（信息泄露面）；
//   - 未闭合的 "${"（可能是截断探测）。
// 仅做检测与净化建议，不依赖正则。净化输出把 "${" 拆开，使表达式无法被解析。

const (
	JNDReasonJNDIInject      = "jndi-lookup-injection"
	JNDReasonNestedObfuscate = "jndi-nested-obfuscation"
	JNDReasonDangerProtocol  = "jndi-danger-protocol"
	JNDReasonInfoLookup      = "jndi-info-lookup"
	JNDReasonUnclosedExpr    = "jndi-unclosed-expression"
	JNDReasonObfuscateSpace  = "jndi-obfuscation-whitespace"
)

// JNDPolicy 控制扫描严格度与信息泄露类查找是否报出。
type JNDPolicy struct {
	MaxTextBytes      int  // 超长文本只扫描前 N 字节，<=0 表示全文
	ReportInfoLookups bool // ${env}/${sys}/${hostName} 等
	ReportUnclosed    bool // 未闭合 ${
	RejectObfuscation bool // 嵌套/空白混淆单独给结论
}

// JNDFinding 记录一处命中。
type JNDFinding struct {
	Reason string
	Offset int
	Token  string
}

// DefaultJNDPolicy 返回默认策略：扫描前 1MiB，信息查找与未闭合均报，混淆报出。
func DefaultJNDPolicy() JNDPolicy {
	return JNDPolicy{
		MaxTextBytes:      1024 * 1024,
		ReportInfoLookups: true,
		ReportUnclosed:    true,
		RejectObfuscation: true,
	}
}

// jndLower 归一小写（仅 ASCII，匹配协议用）。
func jndLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// jndIsSpace 判定表达式内用于混淆的空白（含 Tab/换行/CR）。
func jndIsSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// jndIndexFold 在 s[start:] 内查找与字面量 lit 的大小写无关匹配，返回下标，-1 无。
func jndIndexFold(s string, start int, lit string) int {
	if len(lit) == 0 || start < 0 || start >= len(s) {
		return -1
	}
	for i := start; i+len(lit) <= len(s); i++ {
		ok := true
		for j := 0; j < len(lit); j++ {
			if jndLower(s[i+j]) != lit[j] {
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

// jndDangerProtocol 判断协议名是否为 JNDI 危险协议。
func jndDangerProtocol(p string) (bool, string) {
	// 已归一小写。
	switch p {
	case "ldap", "ldaps", "rmi", "dns", "iiop", "iiopname", "iiopsrmp",
		"corba", "corbaname", "naming", "nis", "nds", "dns://":
		return true, p
	}
	return false, ""
}

// jndInfoLookup 判断是否为信息泄露类查找关键字。
func jndInfoLookup(inner string) (bool, string) {
	// inner 形如 "env:USER" 或 "hostName"。
	name := inner
	if c := indexByteJND(inner, ':'); c >= 0 {
		name = inner[:c]
	}
	switch jndToLowerJND(name) {
	case "env", "sys", "java", "hostname", "date", "marker", "map", "web", "spring":
		return true, name
	}
	return false, ""
}

func indexByteJND(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func jndToLowerJND(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		b[i] = jndLower(b[i])
	}
	return string(b)
}

// jndScanExpressions 枚举所有顶层 ${...} 的内层串（处理嵌套，取最外层闭合）。
// 返回 [{open,close(close 为 '}' 的后一位),inner}]。未闭合的 ${ 单独收集 open 位。
type jndSpan struct {
	open   int
	close  int
	inner  string
	nested bool
}

func jndScanExpressions(s string) ([]jndSpan, []int) {
	var spans []jndSpan
	var unclosed []int
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '$' && s[i+1] == '{' {
			// 找匹配的最外层 }，允许嵌套 ${}。
			depth := 1
			j := i + 2
			nested := false
			closed := false
			for j < len(s) {
				if j+1 < len(s) && s[j] == '$' && s[j+1] == '{' {
					depth++
					nested = true
					j += 2
					continue
				}
				if s[j] == '}' {
					depth--
					if depth == 0 {
						closed = true
						break
					}
				}
				j++
			}
			if closed {
				spans = append(spans, jndSpan{open: i, close: j + 1,
					inner: s[i+2 : j], nested: nested})
				i = j + 1
				continue
			}
			unclosed = append(unclosed, i)
			i += 2
			continue
		}
		i++
	}
	return spans, unclosed
}

// jndCollapseObf 去掉内层里用于绕过的空白与 "${::-x}" 嵌套，尽力还原真实串。
// 例如 "${${::-j}ndi:ldap://x}" 内层为 "${::-j}ndi:ldap://x"，还原为 "jndi:ldap://x"。
func jndCollapseObf(inner string) string {
	out := make([]byte, 0, len(inner))
	i := 0
	for i < len(inner) {
		if i+1 < len(inner) && inner[i] == '$' && inner[i+1] == '{' {
			depth := 1
			j := i + 2
			for j < len(inner) && depth > 0 {
				if j+1 < len(inner) && inner[j] == '$' && inner[j+1] == '{' {
					depth++
				} else if inner[j] == '}' {
					depth--
					if depth == 0 {
						break
					}
				}
				j++
			}
			if j < len(inner) {
				sub := inner[i+2 : j]
				// 仅当嵌套形如 "::-x" / ":x" / "lower:x" 这类单字符变换时取末段字符。
				if c := indexByteJND(sub, ':'); c >= 0 {
					tail := sub[c+1:]
					// 去掉可能的前导 '-'
					for len(tail) > 0 && tail[0] == '-' {
						tail = tail[1:]
					}
					out = append(out, tail...)
				}
				i = j + 1
				continue
			}
		}
		if !jndIsSpace(inner[i]) {
			out = append(out, inner[i])
		}
		i++
	}
	return string(out)
}

// JNDInspect 对一段不可信文本做检测，返回是否安全与全部命中。
func JNDInspect(text string, policy JNDPolicy) (safe bool, findings []JNDFinding) {
	s := text
	if policy.MaxTextBytes > 0 && len(s) > policy.MaxTextBytes {
		s = s[:policy.MaxTextBytes]
	}
	spans, unclosed := jndScanExpressions(s)
	for _, sp := range spans {
		rawInner := sp.inner
		collapsed := jndCollapseObf(rawInner)
		low := jndToLowerJND(collapsed)

		if policy.RejectObfuscation && sp.nested {
			// 只有嵌套且还原后确实拼出危险关键字才报混淆，减少误报。
			if jndIndexFold(low, 0, "jndi:") >= 0 ||
				jndIndexFold(low, 0, "env:") >= 0 ||
				jndIndexFold(low, 0, "sys:") >= 0 {
				findings = append(findings, JNDFinding{Reason: JNDReasonNestedObfuscate,
					Offset: sp.open, Token: s[sp.open:minIntJND(sp.close, len(s))]})
			}
		}
		// 表达式内夹空白混淆：${jndi: ldap://...}
		if policy.RejectObfuscation && containsControlSpaceJND(rawInner) {
			findings = append(findings, JNDFinding{Reason: JNDReasonObfuscateSpace,
				Offset: sp.open, Token: s[sp.open:minIntJND(sp.close, len(s))]})
		}

		// 直接 jndi:<proto>
		if p := jndProtoAfterJND(low); p != "" {
			if danger, name := jndDangerProtocol(p); danger {
				findings = append(findings, JNDFinding{Reason: JNDReasonDangerProtocol,
					Offset: sp.open, Token: name})
			} else {
				findings = append(findings, JNDFinding{Reason: JNDReasonJNDIInject,
					Offset: sp.open, Token: p})
			}
			continue
		}
		if jndIndexFold(low, 0, "jndi:") >= 0 {
			findings = append(findings, JNDFinding{Reason: JNDReasonJNDIInject,
				Offset: sp.open, Token: "jndi"})
			continue
		}
		if policy.ReportInfoLookups {
			if info, name := jndInfoLookup(low); info {
				findings = append(findings, JNDFinding{Reason: JNDReasonInfoLookup,
					Offset: sp.open, Token: name})
			}
		}
	}
	if policy.ReportUnclosed {
		for _, off := range unclosed {
			findings = append(findings, JNDFinding{Reason: JNDReasonUnclosedExpr, Offset: off, Token: "${"})
		}
	}
	return len(findings) == 0, findings
}

// jndProtoAfterJND 在已小写的串里取 "jndi:" 之后到 "://" 之前的协议名。
func jndProtoAfterJND(low string) string {
	idx := jndIndexFold(low, 0, "jndi:")
	if idx < 0 {
		return ""
	}
	rest := low[idx+len("jndi:"):]
	sep := -1
	for k := 0; k+2 < len(rest); k++ {
		if rest[k] == ':' && rest[k+1] == '/' && rest[k+2] == '/' {
			sep = k
			break
		}
	}
	if sep < 0 {
		return ""
	}
	return rest[:sep]
}

func containsControlSpaceJND(s string) bool {
	for i := 0; i < len(s); i++ {
		if jndIsSpace(s[i]) {
			return true
		}
	}
	return false
}

func minIntJND(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// JNDSanitize 净化文本：把每一处 "${" 替换成 "$ {"，让查找表达式无法被解析。
// 该操作幂等，且不改变可读长度太多。
func JNDSanitize(text string) string {
	out := make([]byte, 0, len(text)+8)
	for i := 0; i < len(text); i++ {
		if i+1 < len(text) && text[i] == '$' && text[i+1] == '{' {
			out = append(out, '$', ' ', '{')
			i++
			continue
		}
		out = append(out, text[i])
	}
	return string(out)
}
