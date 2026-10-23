package main

// headerinjectionguard.go —— 出站 HTTP 头部的 CRLF 注入 / 响应拆分 / obs-fold 裁决内核。
//
// 威胁模型：
//  1. 启动器要向 Mojang / Modrinth / 自建镜像发请求，部分头值来自外部数据：
//     自定义 User-Agent、X-Session、X-Maven-Meta、镜像回写的 set-cookie 透传、
//     服务端 MOTD/服务器名拼进追踪头。若其中含 "\r\n"，对宽松代理/老旧中间盒
//     可造成 HTTP 请求走私 / 响应拆分（HTTP request/response splitting）；
//  2. obs-fold（在新行以空格/TAB 续行）在 RFC 7230 已废弃，但仍被部分组件接受，
//     可用来折叠出一个伪造头；单独的 CR 或裸 LF 在不同实现里也可能被当作分隔；
//  3. 头名不合法（空格、冒号、非 token 字符）会让 Go net/http 直接报错，属可被
//     远端输入触发的拒绝服务点；NUL 等控制字符造成日志截断；
//  4. 客户端私设 X-Forwarded-For / X-Real-IP / Host，欺骗服务端或内网旁路的 ACL；
//  5. 单个头或整组头体积过大，用于打满上游缓冲区。
//
// 本模块只做"校验 + 安全裁决"，不负责真正发请求；net/http 已会拒绝多数非法值，
// 这里在拼装阶段提前拦截并给出结构化原因，避免把脏数据带进连接或日志。纯字符判定。

import "strings"

const (
	HIReasonEmptyName        = "hi-empty-header-name"
	HIReasonNameNotToken     = "hi-header-name-not-token"
	HIReasonEmptyValue       = "hi-empty-header-value"
	HIReasonCRLF             = "hi-value-contains-crlf"
	HIReasonBareCR           = "hi-value-contains-bare-cr"
	HIReasonBareLF           = "hi-value-contains-bare-lf"
	HIReasonNUL              = "hi-value-contains-nul"
	HIReasonControlChar      = "hi-value-contains-control-char"
	HIReasonObsFold          = "hi-value-obs-fold"
	HIReasonNonASCII         = "hi-value-non-ascii"
	HIReasonValueTooLong     = "hi-header-value-too-long"
	HIReasonMapTooLarge      = "hi-header-map-too-large"
	HIReasonSpoofedForwarded = "hi-spoofed-forwarding-header"
	HIReasonHostForbidden    = "hi-client-set-host-forbidden"
	HIReasonTooManyValues    = "hi-too-many-values"
)

// HIPolicy 控制头部校验严格度。
type HIPolicy struct {
	AllowTabInValue      bool              // 是否允许值中出现水平制表符（RFC 允许但易与折叠混淆）
	AllowNonASCII        bool              // 是否允许非 ASCII（允许时上层应自行编码）
	MaxHeaderValueBytes  int               // 单个头值上限
	MaxHeaderTotalBytes  int               // 整组头累计上限
	MaxValuesPerHeader   int               // 单个头的取值条数上限
	ForbiddenClientNames []string          // 客户端不得私设的头（转发链/连接控制）
	ValueAllowlist       map[string][]string // 仅允许枚举值的头（大小写不敏感键）
}

// HIFinding 记录一处不合法头部。
type HIFinding struct {
	Name   string
	Reason string
	Offset int
}

// DefaultHIPolicy 返回面向"启动器作为客户端"的严格默认策略。
func DefaultHIPolicy() HIPolicy {
	return HIPolicy{
		AllowTabInValue:     false,
		AllowNonASCII:       false,
		MaxHeaderValueBytes: 8 * 1024,
		MaxHeaderTotalBytes: 64 * 1024,
		MaxValuesPerHeader:  16,
		ForbiddenClientNames: []string{
			"Host",
			"X-Forwarded-For",
			"X-Forwarded-Host",
			"X-Forwarded-Proto",
			"X-Real-IP",
			"Forwarded",
			"Transfer-Encoding",
			"Connection",
			"Content-Length",
		},
		ValueAllowlist: map[string][]string{},
	}
}

// hiIsTokenByte 判断 RFC 7230 token 字符（头名字符集）。
func hiIsTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// HIValidateHeaderName 校验头名是否为合法 token，且非空、不含冒号。
func HIValidateHeaderName(name string) (string, HIFinding) {
	if name == "" {
		return HIReasonEmptyName, HIFinding{Name: name, Reason: HIReasonEmptyName}
	}
	for i := 0; i < len(name); i++ {
		if !hiIsTokenByte(name[i]) {
			return HIReasonNameNotToken, HIFinding{Name: name, Reason: HIReasonNameNotToken, Offset: i}
		}
	}
	return "", HIFinding{}
}

// hiCanonicalLower 把头名归一小写用于策略匹配（不依赖 net/http 导出）。
func hiCanonicalLower(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// HIValidateHeaderValue 校验单个头值。返回首个违规原因与位置。
func HIValidateHeaderValue(name, value string, pol HIPolicy) (string, HIFinding) {
	if value == "" {
		return HIReasonEmptyValue, HIFinding{Name: name, Reason: HIReasonEmptyValue}
	}
	// 首字节为空格/TAB 即疑似 obs-fold 续行。
	first := value[0]
	if first == ' ' || first == '\t' {
		return HIReasonObsFold, HIFinding{Name: name, Reason: HIReasonObsFold, Offset: 0}
	}
	last := value[len(value)-1]
	if last == ' ' || last == '\t' {
		return HIReasonObsFold, HIFinding{Name: name, Reason: HIReasonObsFold, Offset: len(value) - 1}
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		switch b {
		case '\r':
			// CRLF 与裸 CR 都拦。
			if i+1 < len(value) && value[i+1] == '\n' {
				return HIReasonCRLF, HIFinding{Name: name, Reason: HIReasonCRLF, Offset: i}
			}
			return HIReasonBareCR, HIFinding{Name: name, Reason: HIReasonBareCR, Offset: i}
		case '\n':
			return HIReasonBareLF, HIFinding{Name: name, Reason: HIReasonBareLF, Offset: i}
		case 0:
			return HIReasonNUL, HIFinding{Name: name, Reason: HIReasonNUL, Offset: i}
		case '\t':
			if !pol.AllowTabInValue {
				return HIReasonControlChar, HIFinding{Name: name, Reason: HIReasonControlChar, Offset: i}
			}
		default:
			if b < 0x20 || b == 0x7f {
				return HIReasonControlChar, HIFinding{Name: name, Reason: HIReasonControlChar, Offset: i}
			}
			if b >= 0x80 && !pol.AllowNonASCII {
				return HIReasonNonASCII, HIFinding{Name: name, Reason: HIReasonNonASCII, Offset: i}
			}
		}
	}
	if pol.MaxHeaderValueBytes > 0 && len(value) > pol.MaxHeaderValueBytes {
		return HIReasonValueTooLong, HIFinding{Name: name, Reason: HIReasonValueTooLong, Offset: len(value)}
	}
	if allowed, ok := pol.ValueAllowlist[hiCanonicalLower(name)]; ok && len(allowed) > 0 {
		matched := false
		for _, a := range allowed {
			if value == a {
				matched = true
				break
			}
		}
		if !matched {
			return HIReasonValueTooLong, HIFinding{Name: name, Reason: "hi-value-not-in-allowlist"}
		}
	}
	return "", HIFinding{}
}

// hiNameForbidden 判断该头是否禁止由客户端私设。
func hiNameForbidden(name string, pol HIPolicy) bool {
	lower := hiCanonicalLower(name)
	for _, f := range pol.ForbiddenClientNames {
		if lower == hiCanonicalLower(f) {
			return true
		}
	}
	return false
}

// HICheckHeaderMap 校验单值头集合（map 形式）。
func HICheckHeaderMap(headers map[string]string, pol HIPolicy) []HIFinding {
	var findings []HIFinding
	total := 0
	for name, value := range headers {
		if reason, f := HIValidateHeaderName(name); reason != "" {
			findings = append(findings, f)
			continue
		}
		if hiNameForbidden(name, pol) {
			reason := HIReasonSpoofedForwarded
			if hiCanonicalLower(name) == "host" {
				reason = HIReasonHostForbidden
			}
			findings = append(findings, HIFinding{Name: name, Reason: reason})
			continue
		}
		if reason, f := HIValidateHeaderValue(name, value, pol); reason != "" {
			findings = append(findings, f)
			continue
		}
		total += len(name) + len(value)
	}
	if pol.MaxHeaderTotalBytes > 0 && total > pol.MaxHeaderTotalBytes {
		findings = append(findings, HIFinding{Reason: HIReasonMapTooLarge, Offset: total})
	}
	return findings
}

// HICheckRequestHeaders 校验多值头集合（http.Header 形态：名 -> 多值）。
func HICheckRequestHeaders(headers map[string][]string, pol HIPolicy) []HIFinding {
	var findings []HIFinding
	total := 0
	for name, values := range headers {
		if reason, f := HIValidateHeaderName(name); reason != "" {
			findings = append(findings, f)
			continue
		}
		if hiNameForbidden(name, pol) {
			reason := HIReasonSpoofedForwarded
			if hiCanonicalLower(name) == "host" {
				reason = HIReasonHostForbidden
			}
			findings = append(findings, HIFinding{Name: name, Reason: reason})
			continue
		}
		if pol.MaxValuesPerHeader > 0 && len(values) > pol.MaxValuesPerHeader {
			findings = append(findings, HIFinding{Name: name, Reason: HIReasonTooManyValues})
			continue
		}
		for _, v := range values {
			if reason, f := HIValidateHeaderValue(name, v, pol); reason != "" {
				findings = append(findings, f)
				continue
			}
			total += len(name) + len(v)
		}
	}
	if pol.MaxHeaderTotalBytes > 0 && total > pol.MaxHeaderTotalBytes {
		findings = append(findings, HIFinding{Reason: HIReasonMapTooLarge, Offset: total})
	}
	return findings
}

// HISafeHeaderValue 在必须容错的场合做降级清洗：去掉 CR/LF/NUL/其它控制字符，
// 折叠首尾空白；返回清洗结果与是否发生改动。优先应使用拒绝而非清洗。
func HISafeHeaderValue(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(value))
	changed := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\r' || c == '\n' || c == 0 || (c < 0x20 && c != '\t') || c == 0x7f {
			changed = true
			continue
		}
		b.WriteByte(c)
	}
	out := strings.TrimSpace(b.String())
	if out != value {
		changed = true
	}
	return out, changed
}
