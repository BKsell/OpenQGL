package main

import (
	"sync"
	"time"
)

// simpleRateLimiter 是一个内存固定窗口限流器。
// 用于给登录 / 外置登录刷新等敏感接口加一层保护，
// 防止恶意前端或被攻陷的 webview 短时间内把上游认证端点打爆。
type simpleRateLimiter struct {
	mu        sync.Mutex
	windows   map[string]*rateWindow
	maxBurst  int
	window    time.Duration
	lastPurge time.Time
}

type rateWindow struct {
	count   int
	resetAt time.Time
}

// evictSweepAt 是 map 至少长到这个规模才触发一次全表清扫的阈值。
// key 数量很小时清扫毫无收益，频繁全表遍历反而浪费。
const evictSweepAt = 256

func newRateLimiter(maxBurst int, window time.Duration) *simpleRateLimiter {
	return &simpleRateLimiter{
		windows:   make(map[string]*rateWindow),
		maxBurst:  maxBurst,
		window:    window,
		lastPurge: time.Now(),
	}
}

// purgeExpired 删除所有已过期窗口。调用方必须持有 mu。
//
// 这一步必须有：Allow 的 key 直接拼了用户名（"ygg-"+username 等），
// 攻击者可以不断换名字制造海量唯一 key，旧实现从不删除过期项，
// map 会随时间无界增长，最终把内存吃光（自造 DoS）。
func (l *simpleRateLimiter) purgeExpired(now time.Time) {
	for k, w := range l.windows {
		if now.After(w.resetAt) {
			delete(l.windows, k)
		}
	}
	l.lastPurge = now
}

// Allow 报告 key 这次调用是否被允许。超过 maxBurst 的调用直接拒绝。
func (l *simpleRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	// 距离上次清扫超过一个窗口，或 key 数已偏多，就顺手清掉过期项。
	if len(l.windows) >= evictSweepAt || now.Sub(l.lastPurge) >= l.window {
		l.purgeExpired(now)
	}

	w, ok := l.windows[key]
	if !ok || now.After(w.resetAt) {
		l.windows[key] = &rateWindow{count: 1, resetAt: now.Add(l.window)}
		return true
	}
	if w.count >= l.maxBurst {
		return false
	}
	w.count++
	return true
}

// 全局限流器：登录类接口 5 分钟内最多 10 次。
var authRateLimiter = newRateLimiter(10, 5*time.Minute)
