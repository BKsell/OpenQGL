package main

// ratelimitguard.go —— 出向请求的限速、重试放大与并发风暴守卫。
//
// 背景：
//   启动器会并发拉取版本清单、几十个 library、assets、Modrinth 依赖。不受控的请求节奏本身就是
//   安全/稳健问题，也可能被一个恶意或故障的服务端放大成自我 DoS：
//     - 无全局速率上限：数百个连接同时打到一个主机，触发对方封禁或耗尽本机端口/句柄；
//     - 失败后立即无退避重试（tight retry loop），在 5xx/连接被拒时形成放大；
//     - 无最大重试次数，或对 4xx（401/403/404）也盲目重试；
//     - 重试时不遵守 Retry-After，或跨重定向保留同一高压节奏；
//     - 并发下载数无上限，或每个分片各自重试导致 N×M 放大；
//     - 对同一失败主机没有熔断，持续把令牌/连接投向已知不可达端点。
//   本模块审计一份"客户端请求策略"配置是否具备这些闸门，纯数值/布尔判定，不使用正则。

const (
	RLMReasonNoGlobalQPS       = "ratelimit-no-global-rate-cap"
	RLMReasonNoPerHostQPS      = "ratelimit-no-per-host-rate-cap"
	RLMReasonNoConcurrencyCap  = "ratelimit-no-concurrency-cap"
	RLMReasonUnboundedRetries  = "ratelimit-unbounded-retry-count"
	RLMReasonNoBackoff         = "ratelimit-retry-without-backoff"
	RLMReasonRetryOn4xx        = "ratelimit-retries-non-retryable-4xx"
	RLMReasonIgnoresRetryAfter = "ratelimit-ignores-retry-after-header"
	RLMReasonShardRetryAmplify = "ratelimit-shard-retry-amplification"
	RLMReasonNoCircuitBreaker  = "ratelimit-no-circuit-breaker-for-failing-host"
	RLMReasonBackoffNotCapped  = "ratelimit-backoff-without-max-ceiling"
)

// RLMPolicy 描述出向请求/重试策略。
type RLMPolicy struct {
	GlobalQPSPerSec          int // 全局每秒请求上限，0 表示无
	PerHostQPSPerSec         int
	MaxConcurrency           int
	MaxRetries               int // -1/极大值视为无限
	HasExponentialBackoff    bool
	BackoffCeilingMillis     int // 退避上限，0 表示无上限
	RespectsRetryAfter       bool
	RetriesOn4xx             bool
	PerShardIndependentRetry bool
	HasCircuitBreaker        bool
}

// RLMFinding 记录一处限速风险。
type RLMFinding struct {
	Reason string
	Detail string
}

// RLMDefaults 给出稳健默认上限（仅作参考基线）。
type RLMDefaults struct {
	GlobalQPS   int
	PerHostQPS  int
	Concurrency int
	MaxRetries  int
}

func DefaultRLMDefaults() RLMDefaults {
	return RLMDefaults{GlobalQPS: 64, PerHostQPS: 16, Concurrency: 8, MaxRetries: 3}
}

// RLMEvaluate 审计策略。hardFail=true 时缺失关键闸门即视为不合规。
func RLMEvaluate(p RLMPolicy) (safe bool, findings []RLMFinding) {
	d := DefaultRLMDefaults()
	add := func(reason, detail string) {
		findings = append(findings, RLMFinding{Reason: reason, Detail: detail})
	}

	if p.GlobalQPSPerSec <= 0 {
		add(RLMReasonNoGlobalQPS, "global-qps=0")
	} else if p.GlobalQPSPerSec > 256 {
		add(RLMReasonNoGlobalQPS, "global-qps-too-high")
	}
	if p.PerHostQPSPerSec <= 0 {
		add(RLMReasonNoPerHostQPS, "perhost-qps=0")
	} else if p.PerHostQPSPerSec > d.GlobalQPS {
		add(RLMReasonNoPerHostQPS, "perhost-exceeds-global")
	}
	if p.MaxConcurrency <= 0 {
		add(RLMReasonNoConcurrencyCap, "concurrency=0")
	} else if p.MaxConcurrency > 64 {
		add(RLMReasonNoConcurrencyCap, "concurrency-too-high")
	}

	if p.MaxRetries < 0 || p.MaxRetries > 8 {
		add(RLMReasonUnboundedRetries, rlmItoa(p.MaxRetries))
	}
	if p.MaxRetries > 0 && !p.HasExponentialBackoff {
		add(RLMReasonNoBackoff, "tight-loop")
	}
	if p.HasExponentialBackoff && p.BackoffCeilingMillis <= 0 {
		add(RLMReasonBackoffNotCapped, "no-ceiling")
	}
	if p.MaxRetries > 0 && !p.RespectsRetryAfter {
		add(RLMReasonIgnoresRetryAfter, "retry-after")
	}
	if p.RetriesOn4xx {
		add(RLMReasonRetryOn4xx, "4xx")
	}
	if p.PerShardIndependentRetry {
		add(RLMReasonShardRetryAmplify, "N*M")
	}
	if !p.HasCircuitBreaker {
		add(RLMReasonNoCircuitBreaker, "breaker")
	}
	return len(findings) == 0, findings
}

// RLMBackoff 计算指数退避（毫秒），含上限与抖动预留。attempt 从 1 开始。
func RLMBackoff(baseMillis, ceilingMillis int, attempt int) int {
	if attempt < 1 {
		attempt = 1
	}
	if baseMillis <= 0 {
		baseMillis = 250
	}
	// 1<<(attempt-1)，用循环避免大数移位溢出
	d := baseMillis
	for i := 1; i < attempt; i++ {
		if d > ceilingMillis/2+1 {
			d = ceilingMillis
			break
		}
		d *= 2
		if ceilingMillis > 0 && d > ceilingMillis {
			d = ceilingMillis
			break
		}
	}
	if ceilingMillis > 0 && d > ceilingMillis {
		d = ceilingMillis
	}
	return d
}

// RLMShouldRetryStatus 判断某 HTTP 状态码是否值得重试（仅 408/429 与 5xx）。
func RLMShouldRetryStatus(status int) bool {
	if status == 408 || status == 429 {
		return true
	}
	return status >= 500 && status <= 599
}

func rlmItoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		return "<0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
