package main

import (
	"testing"
	"time"
)

func TestCSNoTrustedSource(t *testing.T) {
	m := NewCSMonitor(DefaultCSPolicy())
	r := m.EvaluateSkew(time.Now())
	if r.Safe || !r.HasReason(CSReasonNoTrustedSource) {
		t.Fatalf("want no trusted source, safe=%v %v", r.Safe, r.Findings)
	}
}

func TestCSClockAccurate(t *testing.T) {
	m := NewCSMonitor(DefaultCSPolicy())
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	m.AddTrustedSample(CSTrustedSample{Source: "a", ServerTime: now, ObservedAt: now})
	m.AddTrustedSample(CSTrustedSample{Source: "b", ServerTime: now.Add(2 * time.Second), ObservedAt: now})
	r := m.EvaluateSkew(now)
	if !r.Safe {
		t.Fatalf("accurate clock should be safe: %v", r.Findings)
	}
}

func TestCSSkewTooLarge(t *testing.T) {
	m := NewCSMonitor(DefaultCSPolicy())
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	server := now.Add(10 * time.Minute) // 本地慢 10 分钟
	m.AddTrustedSample(CSTrustedSample{Source: "a", ServerTime: server, ObservedAt: now})
	r := m.EvaluateSkew(now)
	if !r.HasReason(CSReasonSkewTooLarge) {
		t.Fatalf("want skew too large: %v", r.Findings)
	}
}

func TestCSClockWentBackward(t *testing.T) {
	m := NewCSMonitor(DefaultCSPolicy())
	t1 := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	m.ObserveTick(t1, 1000)
	safe, fs := m.ObserveTick(t1.Add(-time.Minute), 2000)
	if safe || len(fs) == 0 {
		t.Fatalf("want backward wall clock, safe=%v fs=%v", safe, fs)
	}
}

func TestCSMonotonicForwardJump(t *testing.T) {
	m := NewCSMonitor(DefaultCSPolicy())
	t1 := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	m.ObserveTick(t1, 0)
	// 墙上正常前进 1 秒，但单调读数跳了 2 小时（虚拟机挂起恢复）
	safe, fs := m.ObserveTick(t1.Add(time.Second), 2*time.Hour)
	if safe {
		t.Fatalf("want monotonic jump: %v", fs)
	}
}

func TestCSMonotonicBackward(t *testing.T) {
	m := NewCSMonitor(DefaultCSPolicy())
	t1 := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	m.ObserveTick(t1, 5000)
	safe, fs := m.ObserveTick(t1.Add(time.Second), 4000)
	if safe {
		t.Fatalf("want monotonic backward: %v", fs)
	}
}

func TestCSTrustedStale(t *testing.T) {
	m := NewCSMonitor(DefaultCSPolicy())
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	yesterday := now.Add(-25 * time.Hour)
	m.AddTrustedSample(CSTrustedSample{Source: "old", ServerTime: yesterday, ObservedAt: yesterday})
	r := m.EvaluateSkew(now)
	if !r.HasReason(CSReasonTrustedStale) {
		t.Fatalf("want stale trusted sample: %v", r.Findings)
	}
}

func TestCSConflictingSources(t *testing.T) {
	m := NewCSMonitor(DefaultCSPolicy())
	now := time.Now()
	m.AddTrustedSample(CSTrustedSample{Source: "a", ServerTime: now, ObservedAt: now})
	m.AddTrustedSample(CSTrustedSample{Source: "b", ServerTime: now.Add(30 * time.Minute), ObservedAt: now})
	r := m.EvaluateSkew(now)
	if !r.HasReason(CSReasonConflictingSources) {
		t.Fatalf("want conflicting sources: %v", r.Findings)
	}
}

func TestCSTokenValidWithinSkew(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	nbf := now.Add(2 * time.Minute) // 尚未到生效时间，但在 5 分钟容错内
	exp := now.Add(time.Hour)
	if !TokenValidWithSkew(nbf, exp, now, 5*time.Minute) {
		t.Fatal("token within skew tolerance should be valid")
	}
}

func TestCSTokenExpiredBeyondSkew(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	nbf := now.Add(-time.Hour)
	exp := now.Add(-10 * time.Minute) // 已过期 10 分钟，超出 5 分钟容错
	if TokenValidWithSkew(nbf, exp, now, 5*time.Minute) {
		t.Fatal("expired token beyond skew must be invalid")
	}
}

func TestCSTokenNotYetValidBeyondSkew(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	nbf := now.Add(30 * time.Minute)
	exp := now.Add(time.Hour)
	if TokenValidWithSkew(nbf, exp, now, 5*time.Minute) {
		t.Fatal("token far in the future must be invalid")
	}
}

func TestCSNormalTicksNoFinding(t *testing.T) {
	m := NewCSMonitor(DefaultCSPolicy())
	base := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		safe, fs := m.ObserveTick(base.Add(time.Duration(i)*time.Second),
			time.Duration(i)*time.Second)
		if !safe {
			t.Fatalf("normal ticks must be safe at %d: %v", i, fs)
		}
	}
}
