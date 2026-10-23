package main

// fragmentleakguard.go —— URI fragment（# 后片段）外发/日志泄漏守卫。
//
// 背景：
//   按 RFC 3986，fragment 由用户代理本地处理，绝不应出现在请求行、转发目标、Referer 或服务端日志里。
//   OAuth 隐式流等历史做法把 access_token 放在 fragment（https://app/cb#access_token=...）。启动器
//   若直接把整条 URL 喂给 HTTP 客户端、写进日志、拼到 Referer、或跨主机重定向时不剥离，就会把令牌
//   泄漏给服务器、代理、CDN 日志或第三方：
//     - 请求目标/重定向 Location 带 fragment；
//     - 日志/错误信息记录含敏感 fragment 的完整 URL；
//     - fragment 跨源保留（导航到别的 host 仍带着 token）；
//     - fragment 里塞控制字符/伪造查询。
//   本模块提供 fragment 提取、敏感片段识别、跨主机保留检测与安全剥离；纯字符串处理，不用正则。

const (
	FRReasonFragmentInRequestTarget = "fragment-present-in-request-target"
	FRReasonSensitiveFragment       = "fragment-carries-sensitive-token"
	FRReasonFragmentKeptCrossOrigin = "fragment-retained-on-cross-origin-navigation"
	FRReasonFragmentControlChar     = "fragment-contains-control-char"
	FRReasonFragmentToLog           = "fragment-must-be-stripped-before-logging"
)

// FRFinding 记录一处 fragment 风险。
type FRFinding struct {
	Reason string
	Detail string
}

// FRSplitResult 拆分结果。
type FRSplitResult struct {
	Base     string // # 之前（可安全外发的部分）
	Fragment string // # 之后（不含 #）
	HasFrag  bool
}

var frSensitiveKeys = map[string]bool{
	"access_token": true, "id_token": true, "token": true,
	"refresh_token": true, "code": true, "password": true, "secret": true,
	"session": true, "api_key": true, "apikey": true,
}

// FRSplit 把 URL 拆成 base 与 fragment（只认第一个 #）。
func FRSplit(rawURL string) FRSplitResult {
	for i := 0; i < len(rawURL); i++ {
		if rawURL[i] == '#' {
			return FRSplitResult{
				Base: rawURL[:i], Fragment: rawURL[i+1:], HasFrag: true}
		}
	}
	return FRSplitResult{Base: rawURL}
}

// FRAuditRequest 审计一个即将作为请求目标/重定向目标的 URL。
func FRAuditRequest(rawURL string) (safeBase string, findings []FRFinding) {
	sp := FRSplit(rawURL)
	if !sp.HasFrag {
		return rawURL, nil
	}
	findings = append(findings, FRFinding{Reason: FRReasonFragmentInRequestTarget})
	if frFragmentSensitive(sp.Fragment) {
		findings = append(findings, FRFinding{Reason: FRReasonSensitiveFragment})
	}
	if frHasControl(sp.Fragment) {
		findings = append(findings, FRFinding{Reason: FRReasonFragmentControlChar})
	}
	return sp.Base, findings
}

// FRAuditLog 审计一条准备写日志的 URL：任何 fragment 都应先剥离。
func FRAuditLog(rawURL string) (safeForLog string, findings []FRFinding) {
	sp := FRSplit(rawURL)
	if sp.HasFrag {
		findings = append(findings, FRFinding{Reason: FRReasonFragmentToLog})
		if frFragmentSensitive(sp.Fragment) {
			findings = append(findings, FRFinding{Reason: FRReasonSensitiveFragment})
		}
		return sp.Base, findings
	}
	return rawURL, nil
}

// FRAuditNavigation 审计导航时 fragment 是否被跨源保留。
// fromHost、toHost 为导航前后主机；toURL 为目标完整 URL。
func FRAuditNavigation(fromHost, toHost, toURL string) (findings []FRFinding) {
	sp := FRSplit(toURL)
	if !sp.HasFrag || sp.Fragment == "" {
		return nil
	}
	if frToLower(fromHost) != frToLower(toHost) && fromHost != "" {
		findings = append(findings, FRFinding{
			Reason: FRReasonFragmentKeptCrossOrigin,
			Detail: frToLower(fromHost) + "->" + frToLower(toHost)})
	}
	if frFragmentSensitive(sp.Fragment) {
		findings = append(findings, FRFinding{Reason: FRReasonSensitiveFragment})
	}
	return findings
}

func frFragmentSensitive(frag string) bool {
	// fragment 形如 k=v&k2=v2，逐个键判断
	start := 0
	for i := 0; i <= len(frag); i++ {
		if i == len(frag) || frag[i] == '&' {
			pair := frag[start:i]
			key := pair
			if eq := frIndex(pair, '='); eq >= 0 {
				key = pair[:eq]
			}
			if frSensitiveKeys[frToLower(frPercentDecode(key))] {
				return true
			}
			start = i + 1
		}
	}
	return false
}

func frHasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7F {
			return true
		}
	}
	return false
}

func frIndex(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func frPercentDecode(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, o1 := frHex(s[i+1]); o1 {
				if lo, o2 := frHex(s[i+2]); o2 {
					out = append(out, hi<<4|lo)
					i += 2
					continue
				}
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}

func frHex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

func frToLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}
