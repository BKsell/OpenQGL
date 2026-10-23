package main

// retrybackoffguard.go —— 出向失败请求的重试安全策略（退避/抖动/幂等/Retry-After）。
//
// 背景：
//   启动器对版本清单、资产下载会自动重试。不设防的重试会放大故障或造成重复副作用：
//     - 固定/零退避 + 无上限重试，在对端 5xx 或超时时形成重试风暴，打爆自己的更新源；
//     - 缺抖动导致大量客户端在同一时刻同步重试（thundering herd）；
//     - 对非幂等方法（POST 登录、上报）在网络超时时盲目重试，造成重复扣款/重复登录态；
//     - 无视服务端 Retry-After（比客户端退避更权威）；
//     - 对 4xx（请求本身错误）也重试，纯属放大。
//   纯策略数值判定，不发起网络，不使用正则。

const (
	RBReasonNonIdempotentRetry = "retry-non-idempotent-method-after-uncertain-result"
	RBReasonClientErrorRetried = "retry-on-4xx-client-error"
	RBReasonNoBackoff          = "retry-without-exponential-backoff"
	RBReasonNoJitter           = "retry-schedule-without-jitter"
	RBReasonTooManyAttempts    = "retry-attempt-count-exceeds-limit"
	RBReasonIgnoresRetryAfter  = "retry-before-server-retry-after-wait"
	RBReasonBackoffOverflow    = "retry-backoff-overflow-without-cap"
)

// RBFinding 记录一处重试策略问题。
type RBFinding struct {
	Reason string
	Detail string
}

// RBPolicy 重试策略。
type RBPolicy struct {
	MaxAttempts      int
	IdempotentMethod bool
	Status           int // 触发重试的响应状态；0 表示网络错误/超时
	BaseDelayMS      int
	MaxDelayMS       int
	GrowthFactor     float64 // 相邻次退避倍数（期望 >=2 才认为是指数）
	HasJitter        bool
	// RetryAfterMS 为服务端 Retry-After（秒换算毫秒）；-1 表示无该头。
	RetryAfterMS int
	// PlannedDelayMS 为客户端计划在下一次重试前等待的毫秒。
	PlannedDelayMS int
	AttemptNumber  int // 即将发生的是第几次重试（首次重试=1）
}

// RBAudit 审计单次重试决策。
func RBAudit(p RBPolicy) (safe bool, findings []RBFinding) {
	if p.MaxAttempts > 0 && p.AttemptNumber > p.MaxAttempts {
		findings = append(findings, RBFinding{Reason: RBReasonTooManyAttempts})
	}
	if !p.IdempotentMethod && p.Status == 0 {
		// 网络结果不确定时，重试非幂等请求可能产生重复副作用
		findings = append(findings, RBFinding{Reason: RBReasonNonIdempotentRetry})
	}
	if p.Status >= 400 && p.Status <= 499 {
		findings = append(findings, RBFinding{Reason: RBReasonClientErrorRetried,
			Detail: rbItoa(p.Status)})
	}

	// 仅对"确实要等待重试"的情形校验退避
	if p.PlannedDelayMS >= 0 && p.AttemptNumber >= 1 {
		expected := rbExpectedDelay(p)
		if p.PlannedDelayMS <= 0 {
			findings = append(findings, RBFinding{Reason: RBReasonNoBackoff})
		} else if expected > 0 && p.PlannedDelayMS < expected {
			findings = append(findings, RBFinding{Reason: RBReasonNoBackoff,
				Detail: "shorter-than-exponential"})
		}
		if !p.HasJitter {
			findings = append(findings, RBFinding{Reason: RBReasonNoJitter})
		}
		if p.MaxDelayMS > 0 && p.PlannedDelayMS > p.MaxDelayMS {
			findings = append(findings, RBFinding{Reason: RBReasonBackoffOverflow})
		}
		if p.RetryAfterMS >= 0 && p.PlannedDelayMS < p.RetryAfterMS {
			findings = append(findings, RBFinding{Reason: RBReasonIgnoresRetryAfter})
		}
	}

	return len(findings) == 0, findings
}

// rbExpectedDelay 计算第 n 次重试的无抖动指数退避下限（用于比较）。
func rbExpectedDelay(p RBPolicy) int {
	if p.BaseDelayMS <= 0 || p.GrowthFactor < 2 {
		// 非指数策略无法给出有意义下限，交由 NoJitter/其它项覆盖
		return 0
	}
	delay := float64(p.BaseDelayMS)
	for i := 1; i < p.AttemptNumber; i++ {
		delay *= p.GrowthFactor
		if p.MaxDelayMS > 0 && delay > float64(p.MaxDelayMS) {
			delay = float64(p.MaxDelayMS)
			break
		}
	}
	return int(delay)
}

func rbItoa(i int) string {
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

// RBHasReason 判定结果含某类问题。
func RBHasReason(findings []RBFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
