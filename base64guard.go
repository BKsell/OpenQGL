package main

// base64guard.go —— Base64/Data-URL 载荷的解码前资源与合法性守卫。
//
// 背景：
//   启动器读取皮肤预览 data: URL、内联图标、配置里的 base64 片段。风险：
//     - 信任声明长度，超长 base64 解码成数倍内存导致 OOM；
//     - 非字母表字符/错误填充使不同解码器产出不同字节；
//     - 填充非法（= 出现在中间、数量不为 0/1/2）；
//     - 内嵌空白外的控制字符、NUL；
//     - data: URL 的 media 段被注入 CRLF 或重复 ;base64 标记。
//   纯字符校验，不实际分配解码缓冲，不使用正则。

const (
	B6ReasonLengthExceedsLimit  = "base64-encoded-length-exceeds-limit"
	B6ReasonDecodedExceedsLimit = "base64-decoded-size-estimate-exceeds-limit"
	B6ReasonInvalidAlphabet     = "base64-contains-non-alphabet-character"
	B6ReasonBadPadding          = "base64-illegal-padding-placement-or-count"
	B6ReasonControlCharacter    = "base64-contains-control-character"
	B6ReasonDataHeaderCRLF      = "data-url-media-section-contains-crlf"
)

const (
	B6MaxEncoded = 32 << 20 // 输入 base64 文本上限 32 MiB
	B6MaxDecoded = 24 << 20 // 估算解码后上限 24 MiB
)

// B6Finding 记录一处问题。
type B6Finding struct {
	Reason string
	Detail string
}

// B6Audit 校验标准 base64（允许换行/制表空白）。
func B6Audit(encoded string) (safe bool, findings []B6Finding) {
	if len(encoded) > B6MaxEncoded {
		findings = append(findings, B6Finding{Reason: B6ReasonLengthExceedsLimit,
			Detail: b6Itoa(int64(len(encoded)))})
	}
	pad := 0
	dataLen := 0
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		if c == '=' {
			pad++
			// 填充后只允许填充或空白
			for j := i + 1; j < len(encoded); j++ {
				if encoded[j] == '=' {
					continue
				}
				if !b6IsSpace(encoded[j]) {
					findings = append(findings, B6Finding{Reason: B6ReasonBadPadding,
						Detail: "data-after-padding"})
					break
				}
			}
			break
		}
		if b6IsSpace(c) {
			continue
		}
		if c < 0x20 || c == 0x7f {
			findings = append(findings, B6Finding{Reason: B6ReasonControlCharacter})
			continue
		}
		if !b6IsAlphabet(c) {
			findings = append(findings, B6Finding{Reason: B6ReasonInvalidAlphabet,
				Detail: string(c)})
			continue
		}
		dataLen++
	}
	if pad > 2 {
		findings = append(findings, B6Finding{Reason: B6ReasonBadPadding, Detail: "pad>2"})
	}
	// 数据字符数（不含填充）必须满足 (dataLen+pad)%4==0
	if (dataLen+pad)%4 != 0 {
		findings = append(findings, B6Finding{Reason: B6ReasonBadPadding, Detail: "length-not-multiple-of-4"})
	}
	// 解码大小估算 ≈ dataLen*3/4
	est := int64(dataLen) * 3 / 4
	if est > B6MaxDecoded {
		findings = append(findings, B6Finding{Reason: B6ReasonDecodedExceedsLimit,
			Detail: b6Itoa(est)})
	}
	return len(findings) == 0, findings
}

// B6AuditDataURL 校验 data:[<mediatype>][;base64],<data> 头段。
func B6AuditDataURL(url string) (safe bool, isBase64 bool, payload string, findings []B6Finding) {
	const prefix = "data:"
	if len(url) < len(prefix) || url[:len(prefix)] != prefix {
		return false, false, "", []B6Finding{{Reason: B6ReasonInvalidAlphabet, Detail: "not-data-url"}}
	}
	comma := -1
	for i := len(prefix); i < len(url); i++ {
		if url[i] == ',' {
			comma = i
			break
		}
		if url[i] == '\r' || url[i] == '\n' {
			findings = append(findings, B6Finding{Reason: B6ReasonDataHeaderCRLF})
		}
	}
	if comma < 0 {
		return false, false, "", append(findings, B6Finding{Reason: B6ReasonBadPadding, Detail: "no-comma"})
	}
	header := url[len(prefix):comma]
	payload = url[comma+1:]
	if b6HasSuffix(header, ";base64") {
		isBase64 = true
		_, fs := B6Audit(payload)
		findings = append(findings, fs...)
	}
	return len(findings) == 0, isBase64, payload, findings
}

func b6IsAlphabet(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '/'
}

func b6IsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func b6HasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

func b6Itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// B6HasReason 判定结果含某类问题。
func B6HasReason(findings []B6Finding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
