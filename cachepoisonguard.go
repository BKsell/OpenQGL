package main

// cachepoisonguard.go —— 出向响应缓存键归一化与缓存投毒（web cache poisoning）检测。
//
// 背景：
//   启动器会缓存版本清单、资源索引、更新元数据。若缓存键只按 URL 而忽略真正影响响应的输入，攻击者
//   可通过一个"带毒"请求让缓存把面向他人的响应存成恶意内容：
//     - 未把 Host/scheme 纳入键（同一反代多 host），或把未受控头（X-Forwarded-Host）拼进 URL；
//     - 响应 Vary 未覆盖键所依赖的请求头，却返回了可缓存的 200；
//     - 依据未在键内的输入做了重定向/绝对 URL 反射（Location 里回显 X-Forwarded-Host）；
//     - 对含 Authorization 的响应给出无 private 指令的可共享缓存；
//     - 302/301 这类跳转被长时间缓存。
//   纯结构判定，不解析真实网络，不使用正则。

const (
	CP2ReasonVaryMismatch           = "cache-vary-does-not-cover-key-inputs"
	CP2ReasonUnkeyedHeaderReflected = "cache-unkeyed-trusted-header-reflected-in-location"
	CP2ReasonSharedWithAuth         = "cache-shared-cacheable-response-to-authorized-request"
	CP2ReasonRedirectCachedLong     = "cache-redirect-with-long-freshness"
	CP2ReasonUncacheableStatus      = "cache-cache-control-on-status-that-must-not-be-stored"
)

// CP2Finding 记录一处缓存投毒风险。
type CP2Finding struct {
	Reason string
	Detail string
}

// CP2Response 描述一次待缓存响应。
type CP2Response struct {
	Status          int
	VaryHeaders     []string // 响应 Vary 列出的请求头（小写）
	KeyInputs       []string // 实际影响响应、应进入键或 Vary 的请求头（小写）
	HasAuthRequest  bool     // 请求是否带 Authorization/Cookie
	CacheDirectives []string // Cache-Control 指令（小写），如 private/public/max-age/no-store
	LocationHeader  string   // 重定向 Location
	ReflectedHeader string   // Location 中回显的未受控请求头（小写），空表示无
}

// CP2Audit 审计可缓存性。
func CP2Audit(resp CP2Response) (safe bool, findings []CP2Finding) {
	vary := map[string]bool{}
	for _, v := range resp.VaryHeaders {
		vary[v] = true
	}
	hasNoStore := false
	hasPrivate := false
	maxAge := -1
	for _, d := range resp.CacheDirectives {
		switch d {
		case "no-store":
			hasNoStore = true
		case "private":
			hasPrivate = true
		}
		if cp2HasPrefix(d, "max-age=") {
			maxAge = cp2Atoi(d[len("max-age="):])
		}
	}

	for _, in := range resp.KeyInputs {
		if !vary[in] && in != "host" && in != "scheme" {
			findings = append(findings, CP2Finding{Reason: CP2ReasonVaryMismatch, Detail: in})
		}
	}

	if resp.ReflectedHeader != "" && !vary[resp.ReflectedHeader] {
		findings = append(findings, CP2Finding{Reason: CP2ReasonUnkeyedHeaderReflected,
			Detail: resp.ReflectedHeader})
	}

	if resp.HasAuthRequest && !hasNoStore && !hasPrivate {
		findings = append(findings, CP2Finding{Reason: CP2ReasonSharedWithAuth})
	}

	if (resp.Status == 301 || resp.Status == 302 || resp.Status == 303 || resp.Status == 307 ||
		resp.Status == 308) && maxAge > 300 {
		findings = append(findings, CP2Finding{Reason: CP2ReasonRedirectCachedLong,
			Detail: cp2Itoa(maxAge)})
	}

	if resp.Status == 204 || resp.Status == 401 || resp.Status == 407 {
		if !hasNoStore {
			findings = append(findings, CP2Finding{Reason: CP2ReasonUncacheableStatus})
		}
	}

	return len(findings) == 0, findings
}

func cp2HasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}

func cp2Atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func cp2Itoa(i int) string {
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

// CP2HasReason 判定结果含某类问题。
func CP2HasReason(findings []CP2Finding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
