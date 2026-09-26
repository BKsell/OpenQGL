package main

import (
	"sync"
	"time"
)

// simpleRateLimiter 是一个内存固定窗口限流器。
// 用于给登录 / 外置登录刷新等敏感接口加一层保护，
// 防止恶意前端或被攻陷的 webview 短时间内把上游认证端点打爆。
type simpleRateLimiter struct {
	mu       sync.Mutex
	windows  map[string]*rateWindow
	maxBurst int
	window   time.Duration
}

type rateWindow struct {
	count    int
	resetAt  time.Time
}

func newRateLimiter(maxBurst int, window time.Duration) *simpleRateLimiter {
	return &simpleRateLimiter{
		windows:  make(map[string]*rateWindow),
		maxBurst: maxBurst,
		window:   window,
	}
}

// Allow 报告 key 这次调用是否被允许。超过 maxBurst 的调用直接拒绝。
func (l *simpleRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
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