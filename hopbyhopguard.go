package main

// hopbyhopguard.go —— 出向/重放请求中逐跳头（hop-by-hop）与连接元数据清除守卫。
//
// 背景：
//   启动器经由本地代理、更新中转或在"重试/跨连接重放"请求时，会复用一组请求头。逐跳头只对单条
//   TCP 连接有意义，若被跨连接、跨代理转发会造成请求走私、连接态混淆或凭据经错误通道发送：
//     - Connection、Keep-Alive、Proxy-Connection、Transfer-Encoding、Upgrade、TE、Trailer；
//     - Connection 头里用枚举字段（Connection: X-Auth）偷偷让代理删除/不转发某头；
//     - 重放时复用了上一条连接的 Authorization-Context / Proxy-Authorization；
//   纯头名集合判定，不使用正则。

// HBHopByHop 是标准逐跳头（小写）集合。
var HBHopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-connection":    true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"te":                  true,
	"trailer":             true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
}

const (
	HBReasonHopByHopForwarded          = "hopbyhop-header-forwarded-across-connections"
	HBReasonConnectionTokenHidesHeader = "hopbyhop-connection-header-lists-a-forwarded-header"
	HBReasonProxyAuthReplayed          = "hopbyhop-proxy-authorization-replayed"
	HBReasonUpgradeReplayed            = "hopbyhop-upgrade-header-replayed"
)

// HBFinding 记录一处逐跳头问题。
type HBFinding struct {
	Reason string
	Header string
}

// HBHeader 是一条请求头。
type HBHeader struct {
	Name  string
	Value string
}

// HBAuditForward 审计准备跨连接/经代理发送的请求头。
func HBAuditForward(headers []HBHeader) (safe bool, findings []HBFinding) {
	hidden := map[string]bool{}
	for _, h := range headers {
		name := hbLower(h.Name)
		if HBHopByHop[name] {
			reason := HBReasonHopByHopForwarded
			if name == "proxy-authorization" {
				reason = HBReasonProxyAuthReplayed
			}
			if name == "upgrade" {
				reason = HBReasonUpgradeReplayed
			}
			findings = append(findings, HBFinding{Reason: reason, Header: name})
		}
		if name == "connection" {
			for _, tok := range hbSplitComma(h.Value) {
				t := hbLower(hbTrim(tok))
				if t != "" && t != "close" && t != "keep-alive" {
					hidden[t] = true
				}
			}
		}
	}
	// 若 Connection 枚举的头确实作为独立头出现，说明有人借逐跳机制操纵转发
	for _, h := range headers {
		name := hbLower(h.Name)
		if hidden[name] {
			findings = append(findings, HBFinding{
				Reason: HBReasonConnectionTokenHidesHeader, Header: name})
		}
	}
	return len(findings) == 0, findings
}

// HBStripHopByHop 返回剔除逐跳头后的可转发头（调用方用于真正重放）。
func HBStripHopByHop(headers []HBHeader) []HBHeader {
	out := make([]HBHeader, 0, len(headers))
	for _, h := range headers {
		if HBHopByHop[hbLower(h.Name)] {
			continue
		}
		out = append(out, h)
	}
	return out
}

func hbLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func hbSplitComma(s string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	out = append(out, cur)
	return out
}

func hbTrim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// HBHasReason 判定结果含某类问题。
func HBHasReason(findings []HBFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
