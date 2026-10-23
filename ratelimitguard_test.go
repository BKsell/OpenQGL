package main

import "testing"

func rlmHas(fs []RLMFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func rlmGood() RLMPolicy {
	return RLMPolicy{
		GlobalQPSPerSec: 32, PerHostQPSPerSec: 8, MaxConcurrency: 6,
		MaxRetries: 3, HasExponentialBackoff: true, BackoffCeilingMillis: 8000,
		RespectsRetryAfter: true, HasCircuitBreaker: true,
	}
}

func TestRLMGood(t *testing.T) {
	safe, _ := RLMEvaluate(rlmGood())
	if !safe {
		t.Fatal("bounded backoff circuit-broken policy should pass")
	}
}

func TestRLMNoGlobal(t *testing.T) {
	p := rlmGood()
	p.GlobalQPSPerSec = 0
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonNoGlobalQPS) {
		t.Fatalf("want no global qps, got %v", fs)
	}
}

func TestRLMNoPerHost(t *testing.T) {
	p := rlmGood()
	p.PerHostQPSPerSec = 0
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonNoPerHostQPS) {
		t.Fatalf("want no perhost, got %v", fs)
	}
}

func TestRLMNoConcurrency(t *testing.T) {
	p := rlmGood()
	p.MaxConcurrency = 0
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonNoConcurrencyCap) {
		t.Fatalf("want no concurrency, got %v", fs)
	}
}

func TestRLMUnboundedRetries(t *testing.T) {
	p := rlmGood()
	p.MaxRetries = -1
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonUnboundedRetries) {
		t.Fatalf("want unbounded, got %v", fs)
	}
}

func TestRLMNoBackoff(t *testing.T) {
	p := rlmGood()
	p.HasExponentialBackoff = false
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonNoBackoff) {
		t.Fatalf("want no backoff, got %v", fs)
	}
}

func TestRLMBackoffNoCeiling(t *testing.T) {
	p := rlmGood()
	p.BackoffCeilingMillis = 0
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonBackoffNotCapped) {
		t.Fatalf("want no ceiling, got %v", fs)
	}
}

func TestRLMIgnoresRetryAfter(t *testing.T) {
	p := rlmGood()
	p.RespectsRetryAfter = false
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonIgnoresRetryAfter) {
		t.Fatalf("want ignores retry-after, got %v", fs)
	}
}

func TestRLMRetry4xx(t *testing.T) {
	p := rlmGood()
	p.RetriesOn4xx = true
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonRetryOn4xx) {
		t.Fatalf("want 4xx retry, got %v", fs)
	}
}

func TestRLMShardAmplify(t *testing.T) {
	p := rlmGood()
	p.PerShardIndependentRetry = true
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonShardRetryAmplify) {
		t.Fatalf("want shard amplify, got %v", fs)
	}
}

func TestRLMNoBreaker(t *testing.T) {
	p := rlmGood()
	p.HasCircuitBreaker = false
	_, fs := RLMEvaluate(p)
	if !rlmHas(fs, RLMReasonNoCircuitBreaker) {
		t.Fatalf("want no breaker, got %v", fs)
	}
}

func TestRLMBackoffSequence(t *testing.T) {
	base, ceil := 250, 8000
	if got := RLMBackoff(base, ceil, 1); got != 250 {
		t.Fatalf("attempt1=%d", got)
	}
	if got := RLMBackoff(base, ceil, 2); got != 500 {
		t.Fatalf("attempt2=%d", got)
	}
	if got := RLMBackoff(base, ceil, 3); got != 1000 {
		t.Fatalf("attempt3=%d", got)
	}
	if got := RLMBackoff(base, ceil, 20); got != 8000 {
		t.Fatalf("capped=%d", got)
	}
}

func TestRLMRetryableStatus(t *testing.T) {
	cases := map[int]bool{408: true, 429: true, 500: true, 503: true, 200: false, 404: false, 401: false, 403: false}
	for status, want := range cases {
		if got := RLMShouldRetryStatus(status); got != want {
			t.Fatalf("status %d retry=%v want %v", status, got, want)
		}
	}
}
