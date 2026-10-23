package main

// utf7guard.go —— UTF-7 隐式编码的 XSS/控制字符注入守卫。
//
// 背景：
//   UTF-7 用 +BASE64- 形式表示任意 Unicode，老的 IE/某些嵌入 WebView、以及把页面按 Auto-Select
//   解码的组件会把普通 ASCII 文本里的 "+ADw-script+AD4-" 还原成 "<script>"，从而绕过只过滤字面
//   "<" 的 XSS 防护。启动器的富文本/MOTD/书签标题若进入这类解码上下文就有风险。
//   本模块检测可疑 UTF-7 移位序列与可还原出的危险字符（< > 等），不实际解码执行，不使用正则。

const (
	U7ReasonShiftSequence = "utf7-shift-sequence-present"
	U7ReasonEncodesAngle  = "utf7-sequence-decodes-to-angle-bracket-or-control"
	U7ReasonSetO          = "utf7-set-o-optional-direct-characters"
)

// U7Finding 记录一处问题。
type U7Finding struct {
	Reason string
	Index  int
	Detail string
}

// U7Audit 检测输入中的 UTF-7 风险。
func U7Audit(input string) (safe bool, findings []U7Finding) {
	i := 0
	for i < len(input) {
		if input[i] != '+' {
			i++
			continue
		}
		// "+-" 是转义的字面 +，合法
		if i+1 < len(input) && input[i+1] == '-' {
			i += 2
			continue
		}
		// 从 + 后收集 base64 字符直到终止符 '-' 或非 base64 字符
		j := i + 1
		start := j
		for j < len(input) && u7IsB64(input[j]) {
			j++
		}
		b64part := input[start:j]
		if j < len(input) && input[j] == '-' && b64part != "" {
			findings = append(findings, U7Finding{Reason: U7ReasonShiftSequence, Index: i,
				Detail: b64part})
			if u7DecodesToDanger(b64part) {
				findings = append(findings, U7Finding{Reason: U7ReasonEncodesAngle, Index: i,
					Detail: b64part})
			}
			i = j + 1
			continue
		}
		// 未终止的 +BASE64（没有 '-'），旧解码器也可能贪婪解释
		if b64part != "" && u7DecodesToDanger(b64part) {
			findings = append(findings, U7Finding{Reason: U7ReasonShiftSequence, Index: i,
				Detail: b64part})
		}
		i++
	}
	return len(findings) == 0, findings
}

// u7DecodesToDanger 判断该 base64 片段按 UTF-7（UTF-16BE 码元的 base64）能否还原出 '<'(0x3C)、
// '>'(0x3E) 或 C0 控制字符。这里做轻量判定：base64 解码后按 16bit 大端码元扫描。
func u7DecodesToDanger(b64 string) bool {
	raw := u7DecodeB64(b64)
	for k := 0; k+1 < len(raw); k += 2 {
		unit := uint16(raw[k])<<8 | uint16(raw[k+1])
		if unit == '<' || unit == '>' || unit < 0x20 {
			return true
		}
	}
	return false
}

// u7DecodeB64 最小化 base64 解码（仅用于静态判断，忽略尾部不足）。
func u7DecodeB64(s string) []byte {
	var out []byte
	var buf uint32
	bits := 0
	for i := 0; i < len(s); i++ {
		d := u7Val(s[i])
		if d < 0 {
			break
		}
		buf = (buf << 6) | uint32(d)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>uint(bits)))
			buf &= (1 << uint(bits)) - 1
		}
	}
	return out
}

func u7Val(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '+':
		return 62
	case c == '/':
		return 63
	}
	return -1
}

func u7IsB64(c byte) bool {
	return u7Val(c) >= 0
}

// U7HasReason 判定结果含某类问题。
func U7HasReason(findings []U7Finding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
