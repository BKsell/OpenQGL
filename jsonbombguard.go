package main

// jsonbombguard.go —— JSON 输入炸弹（深度/重复键/巨型标量）守卫。
//
// 背景：
//   启动器解析大量来自网络的 JSON：微软/Xbox/Mojang 认证响应、版本清单、资源索引、Modrinth/
//   CurseForge 元数据、服务器 favicon 内嵌数据。encoding/json 默认：
//     - 接受极深嵌套（深度炸弹），递归解析可撑爆调用栈/内存；
//     - 不限制单个字符串长度（长字符串炸弹）；
//     - 数字可以极长，用 float64 解析超大指数产生 Inf；
//     - 默认允许重复键（后者覆盖前者），攻击者可用重复键投毒/绕过基于键名的安全判断。
//   本模块在交给 encoding/json 之前做一遍纯字节状态机扫描（不使用正则），按策略给出结论，
//   可作为"先验大小/结构闸门"。

const (
	JBGReasonTooDeep       = "jbg-nesting-too-deep"
	JBGReasonStringTooLong = "jbg-string-too-long"
	JBGReasonNumberTooLong = "jbg-number-too-long"
	JBGReasonNumberBadExp  = "jbg-number-bad-exponent"
	JBGReasonDuplicateKey  = "jbg-duplicate-object-key"
	JBGReasonTooManyTokens = "jbg-too-many-tokens"
	JBGReasonInvalidUTF8   = "jbg-invalid-utf8"
	JBGReasonTruncated     = "jbg-truncated-input"
	JBGReasonEmpty         = "jbg-empty-input"
)

// JBGPolicy 设定 JSON 结构闸门。
type JBGPolicy struct {
	MaxDepth          int
	MaxStringLength   int
	MaxNumberLength   int
	MaxTokens         int
	RejectDupKeys     bool
	RejectInvalidUTF8 bool
}

// JBGFinding 记录一处结构风险。
type JBGFinding struct {
	Reason string
	Offset int
	Detail string
}

// DefaultJBGPolicy 返回面向清单/认证响应的保守阈值。
func DefaultJBGPolicy() JBGPolicy {
	return JBGPolicy{
		MaxDepth:          64,
		MaxStringLength:   4 * 1024 * 1024,
		MaxNumberLength:   64,
		MaxTokens:         2000000,
		RejectDupKeys:     true,
		RejectInvalidUTF8: true,
	}
}

type jbgFrame struct {
	isObj     bool
	keys      map[string]bool
	expectKey bool
}

// JBGValidate 对 JSON 字节做结构闸门校验。
func JBGValidate(data []byte, policy JBGPolicy) (safe bool, findings []JBGFinding) {
	if len(data) == 0 {
		return false, []JBGFinding{{Reason: JBGReasonEmpty, Offset: 0}}
	}

	depth := 0
	tokens := 0
	i := 0
	n := len(data)
	var stack []jbgFrame

	skipSpace := func() {
		for i < n {
			c := data[i]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				i++
				continue
			}
			break
		}
	}

	skipSpace()
	haveValue := false
	for i < n {
		skipSpace()
		if i >= n {
			break
		}
		c := data[i]

		if c == '}' || c == ']' {
			if len(stack) == 0 {
				findings = append(findings, JBGFinding{Reason: JBGReasonTruncated, Offset: i, Detail: "extra-close"})
				i++
				continue
			}
			stack = stack[:len(stack)-1]
			depth--
			i++
			haveValue = true
			continue
		}

		if c == ',' {
			i++
			if len(stack) > 0 && stack[len(stack)-1].isObj {
				stack[len(stack)-1].expectKey = true
			}
			continue
		}
		if c == ':' {
			i++
			if len(stack) > 0 {
				stack[len(stack)-1].expectKey = false
			}
			continue
		}

		if c == '{' {
			depth++
			if depth > policy.MaxDepth {
				findings = append(findings, JBGFinding{Reason: JBGReasonTooDeep, Offset: i})
			}
			stack = append(stack, jbgFrame{isObj: true, keys: map[string]bool{}, expectKey: true})
			tokens++
			i++
			haveValue = true
			continue
		}
		if c == '[' {
			depth++
			if depth > policy.MaxDepth {
				findings = append(findings, JBGFinding{Reason: JBGReasonTooDeep, Offset: i})
			}
			stack = append(stack, jbgFrame{isObj: false})
			tokens++
			i++
			haveValue = true
			continue
		}

		if c == '"' {
			startOff := i
			content, ni, okDecode := jbgReadString(data, i)
			if !okDecode {
				findings = append(findings, JBGFinding{Reason: JBGReasonTruncated, Offset: startOff, Detail: "bad-string"})
				return false, findings
			}
			i = ni
			tokens++
			if tokens > policy.MaxTokens {
				findings = append(findings, JBGFinding{Reason: JBGReasonTooManyTokens, Offset: startOff})
			}
			if policy.RejectInvalidUTF8 && !jbgValidUTF8(content) {
				findings = append(findings, JBGFinding{Reason: JBGReasonInvalidUTF8, Offset: startOff})
			}
			if len(content) > policy.MaxStringLength {
				findings = append(findings, JBGFinding{Reason: JBGReasonStringTooLong, Offset: startOff,
					Detail: itoaJBG(len(content))})
			}
			if len(stack) > 0 && stack[len(stack)-1].isObj && stack[len(stack)-1].expectKey {
				if policy.RejectDupKeys {
					if stack[len(stack)-1].keys[content] {
						findings = append(findings, JBGFinding{Reason: JBGReasonDuplicateKey,
							Offset: startOff, Detail: content})
					}
					stack[len(stack)-1].keys[content] = true
				}
				stack[len(stack)-1].expectKey = false
			}
			haveValue = true
			continue
		}

		if c == '-' || (c >= '0' && c <= '9') {
			startOff := i
			numStart := i
			for i < n {
				ch := data[i]
				isNum := (ch >= '0' && ch <= '9') || ch == '-' || ch == '+' ||
					ch == '.' || ch == 'e' || ch == 'E'
				if !isNum {
					break
				}
				i++
			}
			lit := data[numStart:i]
			tokens++
			if len(lit) > policy.MaxNumberLength {
				findings = append(findings, JBGFinding{Reason: JBGReasonNumberTooLong, Offset: startOff})
			}
			if jbgBadNumber(lit) {
				findings = append(findings, JBGFinding{Reason: JBGReasonNumberBadExp, Offset: startOff})
			}
			haveValue = true
			continue
		}

		litLen, litOK := jbgMatchLiteral(data, i)
		if litOK {
			i += litLen
			tokens++
			haveValue = true
			continue
		}

		findings = append(findings, JBGFinding{Reason: JBGReasonTruncated, Offset: i, Detail: "unexpected-char"})
		i++
	}

	if len(stack) != 0 {
		findings = append(findings, JBGFinding{Reason: JBGReasonTruncated, Offset: n, Detail: "unclosed"})
	}
	if !haveValue {
		findings = append(findings, JBGFinding{Reason: JBGReasonEmpty, Offset: 0})
	}
	return len(findings) == 0, findings
}

// jbgReadString 从开头的引号读取 JSON 字符串，返回解码内容与结束下标。
func jbgReadString(data []byte, start int) (content string, next int, ok bool) {
	i := start + 1
	n := len(data)
	var raw []byte
	for i < n {
		c := data[i]
		if c == '"' {
			return string(raw), i + 1, true
		}
		if c == '\\' {
			if i+1 >= n {
				return "", i, false
			}
			esc := data[i+1]
			switch esc {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				raw = append(raw, c, esc)
				i += 2
				continue
			case 'u':
				if i+5 >= n {
					return "", i, false
				}
				raw = append(raw, data[i:i+6]...)
				i += 6
				continue
			default:
				return "", i, false
			}
		}
		if c < 0x20 {
			return "", i, false
		}
		raw = append(raw, c)
		i++
	}
	return "", i, false
}

func jbgMatchLiteral(data []byte, i int) (int, bool) {
	for _, lit := range []string{"true", "false", "null"} {
		if i+len(lit) <= len(data) && string(data[i:i+len(lit)]) == lit {
			return len(lit), true
		}
	}
	return 0, false
}

func jbgBadNumber(lit []byte) bool {
	dots := 0
	exp := -1
	for k := 0; k < len(lit); k++ {
		c := lit[k]
		if c == '.' {
			dots++
		}
		if c == 'e' || c == 'E' {
			if exp >= 0 {
				return true
			}
			exp = k
		}
	}
	if dots > 1 {
		return true
	}
	if exp >= 0 {
		rest := lit[exp+1:]
		if len(rest) == 0 {
			return true
		}
		if rest[0] == '+' || rest[0] == '-' {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return true
		}
		for _, c := range rest {
			if c < '0' || c > '9' {
				return true
			}
		}
	}
	return false
}

func jbgValidUTF8(s string) bool {
	b := []byte(s)
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			i++
			continue
		}
		var need int
		switch {
		case c&0xE0 == 0xC0:
			need = 2
		case c&0xF0 == 0xE0:
			need = 3
		case c&0xF8 == 0xF0:
			need = 4
		default:
			return false
		}
		if i+need > len(b) {
			return false
		}
		for k := 1; k < need; k++ {
			if b[i+k]&0xC0 != 0x80 {
				return false
			}
		}
		i += need
	}
	return true
}

func itoaJBG(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
