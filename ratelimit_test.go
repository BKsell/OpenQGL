package main

import (
	"strconv"
	"testing"
	"time"
)

func TestRateLimiterBurst(t *testing.T) {
	l := newRateLimiter(3, 50*time.Millisecond)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("前 %d 次应放行", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("第 4 次应被限流")
	}
	// 不同 key 互不影响。
	if !l.Allow("other") {
		t.Fatal("其它 key 应有独立窗口")
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	l := newRateLimiter(1, 30*time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("首次应放行")
	}
	if l.Allow("k") {
		t.Fatal("窗口内应被限流")
	}
	time.Sleep(45 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("窗口过期后应重新放行")
	}
}

// TestRateLimiterPurgesExpiredKeys 验证旧实现的内存无界增长问题已修复：
// 大量唯一 key 的窗口过期后，下一次 Allow 触发清扫，过期项必须被回收。
func TestRateLimiterPurgesExpiredKeys(t *testing.T) {
	l := newRateLimiter(1, 10*time.Millisecond)
	for i := 0; i < evictSweepAt+10; i++ {
		l.Allow("user-" + strconv.Itoa(i))
	}
	if len(l.windows) < evictSweepAt {
		t.Fatalf("清扫前应保留这些新窗口，实际 %d", len(l.windows))
	}
	time.Sleep(20 * time.Millisecond)
	l.Allow("trigger") // 此刻所有旧窗口都已过期，应被全表清扫
	if len(l.windows) != 1 {
		t.Fatalf("过期键应被清扫，仅剩 trigger，实际 %d 个", len(l.windows))
	}
}

func TestRateLimiterManualPurge(t *testing.T) {
	l := newRateLimiter(2, time.Hour)
	l.Allow("a")
	l.Allow("b")
	now := time.Now()
	// 手动把一个窗口改成过期，purgeExpired 应只删过期项、保留有效项。
	l.mu.Lock()
	l.windows["a"].resetAt = now.Add(-time.Second)
	l.purgeExpired(now)
	l.mu.Unlock()
	if _, ok := l.windows["a"]; ok {
		t.Fatal("过期窗口 a 应被删除")
	}
	if _, ok := l.windows["b"]; !ok {
		t.Fatal("有效窗口 b 应保留")
	}
}
