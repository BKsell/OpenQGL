package main

// dnsrebindguard.go —— DNS 应答的重绑定（rebinding）与范围混合守卫。
//
// 背景：
//   启动器连接下载/认证主机、SRV 解析的 MC 服务器时，若信任单次 DNS 结果直接连，攻击者控制的
//   权威 DNS 可在两次解析间返回不同地址：第一次返回公网 IP 通过校验，第二次返回 127.0.0.1 /
//   169.254.169.254 / 内网 IP，让带凭证的请求实际打到内网或本机（DNS rebinding）。
//   本模块对"一次解析返回的地址集合"以及"跨两次解析的地址集合"做判定：
//     - 同一名字的 A 记录集合跨公网/私网/环回/链路本地范围（mixed-scope）；
//     - 出现环回/链路本地/私网映射；
//     - TTL 异常短（0/1s）配合多范围；
//     - 校验时解析的地址与真正连接时解析的地址不一致（pin 漂移）。
//   地址分类复用 HSClassifyIP4（v4），不做真实网络调用，不使用正则。

const (
	DRReasonMixedScopeRecords = "dns-answer-set-mixes-public-and-internal-scopes"
	DRReasonInternalRecord    = "dns-answer-contains-loopback-private-or-linklocal"
	DRReasonSuspiciousTTL     = "dns-answer-ttl-zero-or-one-with-mixed-records"
	DRReasonPinDrift          = "dns-rebind-verify-address-differs-from-connect-address"
)

// DRRecord 是一条解析记录。
type DRRecord struct {
	IP  string
	TTL int
}

// DRFinding 记录一处问题。
type DRFinding struct {
	Reason string
	Detail string
}

// DRAuditAnswerSet 审计一次解析返回的全部地址。
func DRAuditAnswerSet(records []DRRecord) (safe bool, findings []DRFinding) {
	scopes := map[HSIPClass]bool{}
	internal := false
	for _, r := range records {
		c := HSClassifyIP4(r.IP)
		scopes[c] = true
		if c == HSIPLoopback || c == HSIPPrivate || c == HSIPLinkLocal {
			internal = true
			findings = append(findings, DRFinding{Reason: DRReasonInternalRecord, Detail: r.IP})
		}
	}
	public := scopes[HSIPPublic]
	if internal && (public || drScopeCount(scopes) > 1) {
		findings = append(findings, DRFinding{Reason: DRReasonMixedScopeRecords})
	}
	for _, r := range records {
		if r.TTL >= 0 && r.TTL <= 1 && drScopeCount(scopes) > 1 {
			findings = append(findings, DRFinding{Reason: DRReasonSuspiciousTTL,
				Detail: drItoa(int64(r.TTL))})
			break
		}
	}
	return len(findings) == 0, findings
}

// DRVerifyPin 校验"做安全校验那次解析"与"真正建连那次解析"地址是否一致。
// verifiedIP 是通过策略校验时使用的地址；connectIP 是实际 TCP 连接时解析到的地址。
func DRVerifyPin(verifiedIP, connectIP string) (safe bool, findings []DRFinding) {
	if verifiedIP != connectIP {
		findings = append(findings, DRFinding{Reason: DRReasonPinDrift,
			Detail: verifiedIP + "->" + connectIP})
	}
	return len(findings) == 0, findings
}

func drScopeCount(m map[HSIPClass]bool) int {
	n := 0
	for _, v := range m {
		if v {
			n++
		}
	}
	return n
}

func drItoa(i int64) string {
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

// DRHasReason 判定结果含某类问题。
func DRHasReason(findings []DRFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
