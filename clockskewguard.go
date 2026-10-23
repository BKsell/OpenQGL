package main

// clockskewguard.go —— 本地时钟偏移与回拨检测（保护证书有效期、token exp、nonce 重放判定）。
//
// 背景：
//   启动器大量安全判定依赖"当前时间"：TLS/证书 NotBefore/NotAfter、OAuth token 的 exp/nbf、state/
//   nonce 的新鲜度、签名时间戳、缓存 TTL。本机时钟一旦偏差或被回拨：
//     - 时钟快于真实：把未到期证书/token 判成已过期，或把重放的旧 nonce 判成"未来才有效"放过；
//     - 时钟慢/回拨：已过期 token 仍被判有效（越权延长会话）、旧 nonce 重放通过、TLS 证书被提前信任；
//     - 单调时钟跳跃（用户改系统时间、NTP 大幅校时、虚拟机挂起恢复）让 TTL 计算错乱。
//   本模块把"可信时间源（TLS Date 响应头、服务端 JSON 时间）"与本地时间比较，并记录单调时钟采样，
//   输出偏移与回拨结论。纯数值逻辑，时间戳由调用方传入，不直接取系统时钟，不使用正则。

import "time"

const (
	CSReasonSkewTooLarge       = "clock-skew-exceeds-tolerance"
	CSReasonClockWentBackward  = "monotonic-clock-went-backward"
	CSReasonMonotonicJump      = "monotonic-clock-large-forward-jump"
	CSReasonNoTrustedSource    = "clock-no-trusted-time-source"
	CSReasonTrustedStale       = "trusted-time-sample-too-old"
	CSReasonConflictingSources = "trusted-time-sources-conflict"
)

// CSPolicy 时钟策略。
type CSPolicy struct {
	MaxSkew             time.Duration // 本地与可信源允许偏差
	MaxMonotonicJump    time.Duration // 单调时钟正向跳跃上限
	TrustedSampleMaxAge time.Duration // 可信时间样本有效期
	MinAgreeingSources  int           // 至少需一致的可信源数量
}

// DefaultCSPolicy 默认偏差 5 分钟、前跳 1 小时、样本有效 24 小时、2 个一致源。
func DefaultCSPolicy() CSPolicy {
	return CSPolicy{
		MaxSkew:             5 * time.Minute,
		MaxMonotonicJump:    time.Hour,
		TrustedSampleMaxAge: 24 * time.Hour,
		MinAgreeingSources:  2,
	}
}

// CSFinding 记录一处时钟风险。
type CSFinding struct {
	Reason string
	Detail string
}

// CSTrustedSample 一个可信时间样本。
type CSTrustedSample struct {
	Source     string
	ServerTime time.Time
	ObservedAt time.Time     // 本地拿到该样本头的时刻
	SampleAge  time.Duration // 样本自被采集到现在的年龄（调用方按 now 计算传入）
}

// CSSkewReport 偏移结论。
type CSSkewReport struct {
	Safe     bool
	Findings []CSFinding
	Skew     time.Duration
}

// CSMonitor 记录单调时钟采样与可信源。
type CSMonitor struct {
	policy       CSPolicy
	lastWall     time.Time
	lastMono     time.Duration
	haveBaseline bool
	samples      []CSTrustedSample
}

// NewCSMonitor 创建监控器。
func NewCSMonitor(policy CSPolicy) *CSMonitor {
	return &CSMonitor{policy: policy}
}

// ObserveTick 喂入一次"墙上时间 + 单调读数"采样，检测回拨与前跳。
func (m *CSMonitor) ObserveTick(wall time.Time, mono time.Duration) (safe bool, findings []CSFinding) {
	if m.haveBaseline {
		if wall.Before(m.lastWall) {
			findings = append(findings, CSFinding{
				Reason: CSReasonClockWentBackward,
				Detail: (m.lastWall.Sub(wall)).String(),
			})
		}
		if mono >= 0 && m.lastMono >= 0 {
			delta := mono - m.lastMono
			if delta < 0 {
				findings = append(findings, CSFinding{Reason: CSReasonClockWentBackward,
					Detail: "monotonic-delta"})
			} else if time.Duration(delta) > m.policy.MaxMonotonicJump {
				findings = append(findings, CSFinding{Reason: CSReasonMonotonicJump,
					Detail: time.Duration(delta).String()})
			}
		}
	}
	m.lastWall = wall
	m.lastMono = mono
	m.haveBaseline = true
	return len(findings) == 0, findings
}

// AddTrustedSample 加入一个可信时间样本（如响应的 Date 头）。
func (m *CSMonitor) AddTrustedSample(s CSTrustedSample) {
	m.samples = append(m.samples, s)
}

// EvaluateSkew 用已采集可信样本评估本地时钟偏移。now 为当前本地墙上时间。
func (m *CSMonitor) EvaluateSkew(now time.Time) CSSkewReport {
	var findings []CSFinding

	if len(m.samples) == 0 {
		return CSSkewReport{Safe: false,
			Findings: []CSFinding{{Reason: CSReasonNoTrustedSource}},
		}
	}

	// 过滤过期样本，取最新有效样本，并统计彼此一致性
	var fresh []CSTrustedSample
	for _, s := range m.samples {
		age := now.Sub(s.ObservedAt)
		if age > m.policy.TrustedSampleMaxAge {
			findings = append(findings, CSFinding{Reason: CSReasonTrustedStale,
				Detail: s.Source})
			continue
		}
		fresh = append(fresh, s)
	}
	if len(fresh) == 0 {
		return CSSkewReport{Safe: false, Findings: findings}
	}

	// 以最新样本为准计算偏差
	latest := fresh[0]
	for _, s := range fresh[1:] {
		if s.ObservedAt.After(latest.ObservedAt) {
			latest = s
		}
	}
	skew := now.Sub(latest.ServerTime)
	absSkew := skew
	if absSkew < 0 {
		absSkew = -absSkew
	}
	if absSkew > m.policy.MaxSkew {
		findings = append(findings, CSFinding{Reason: CSReasonSkewTooLarge,
			Detail: skew.String()})
	}

	// 多个可信源之间偏差是否冲突
	if len(fresh) >= 2 {
		for i := 0; i < len(fresh); i++ {
			for j := i + 1; j < len(fresh); j++ {
				d := fresh[i].ServerTime.Sub(fresh[j].ServerTime)
				if d < 0 {
					d = -d
				}
				if d > m.policy.MaxSkew {
					findings = append(findings, CSFinding{
						Reason: CSReasonConflictingSources,
						Detail: fresh[i].Source + "|" + fresh[j].Source})
				}
			}
		}
	}

	return CSSkewReport{
		Safe:     len(findings) == 0,
		Findings: findings,
		Skew:     skew,
	}
}

// HasReason 判定报告含某类问题。
func (r CSSkewReport) HasReason(reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

// TokenValidWithSkew 在已知最大时钟偏移下保守判定 token 时间有效性：
// 用偏移区间扩大容错，避免因本机时钟误差误杀；但拒绝明显越界。
func TokenValidWithSkew(notBefore, expiresAt, now time.Time, maxSkew time.Duration) bool {
	// 生效时间：允许提前 maxSkew；过期时间：允许延后 maxSkew（双向容错）
	if now.Add(maxSkew).Before(notBefore) {
		return false
	}
	if now.Add(-maxSkew).After(expiresAt) {
		return false
	}
	return true
}
