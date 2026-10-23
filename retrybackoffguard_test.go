package main

import "testing"

func rbHealthy(attempt int) RBPolicy {
	return RBPolicy{
		MaxAttempts: 4, IdempotentMethod: true, Status: 503,
		BaseDelayMS: 100, MaxDelayMS: 10000, GrowthFactor: 2, HasJitter: true,
		RetryAfterMS: -1, AttemptNumber: attempt,
		PlannedDelayMS: 100 * (1 << (attempt - 1)),
	}
}

func TestRBHealthyRetry(t *testing.T) {
	if safe, _ := RBAudit(rbHealthy(2)); !safe {
		t.Fatal("exponential jittered idempotent retry should pass")
	}
}

func TestRBNonIdempotentOnTimeout(t *testing.T) {
	p := rbHealthy(1)
	p.IdempotentMethod = false
	p.Status = 0 // 结果不确定（超时）
	_, fs := RBAudit(p)
	if !RBHasReason(fs, RBReasonNonIdempotentRetry) {
		t.Fatalf("non-idempotent retry on uncertain result must flag: %v", fs)
	}
}

func TestRBClientError(t *testing.T) {
	p := rbHealthy(1)
	p.Status = 404
	_, fs := RBAudit(p)
	if !RBHasReason(fs, RBReasonClientErrorRetried) {
		t.Fatalf("retrying 4xx must flag: %v", fs)
	}
}

func TestRBNoBackoff(t *testing.T) {
	p := rbHealthy(1)
	p.PlannedDelayMS = 0
	_, fs := RBAudit(p)
	if !RBHasReason(fs, RBReasonNoBackoff) {
		t.Fatalf("zero delay must flag: %v", fs)
	}
}

func TestRBTooFastNotExponential(t *testing.T) {
	p := rbHealthy(3)
	p.PlannedDelayMS = 50 // 期望约 400
	_, fs := RBAudit(p)
	if !RBHasReason(fs, RBReasonNoBackoff) {
		t.Fatalf("sub-exponential delay must flag: %v", fs)
	}
}

func TestRBNoJitter(t *testing.T) {
	p := rbHealthy(2)
	p.HasJitter = false
	_, fs := RBAudit(p)
	if !RBHasReason(fs, RBReasonNoJitter) {
		t.Fatalf("missing jitter must flag: %v", fs)
	}
}

func TestRBTooManyAttempts(t *testing.T) {
	p := rbHealthy(5)
	_, fs := RBAudit(p)
	if !RBHasReason(fs, RBReasonTooManyAttempts) {
		t.Fatalf("attempt beyond limit must flag: %v", fs)
	}
}

func TestRBIgnoresRetryAfter(t *testing.T) {
	p := rbHealthy(1)
	p.RetryAfterMS = 5000
	p.PlannedDelayMS = 100
	_, fs := RBAudit(p)
	if !RBHasReason(fs, RBReasonIgnoresRetryAfter) {
		t.Fatalf("retrying before Retry-After must flag: %v", fs)
	}
}

func TestRBDelayCapRespected(t *testing.T) {
	p := rbHealthy(4)
	// base100 *2^3 = 800，被 cap 到 1000，1000 合法
	p.PlannedDelayMS = 1000
	if safe, _ := RBAudit(p); !safe {
		t.Fatal("delay capped at max should pass")
	}
}

func TestRBBackoffOverflow(t *testing.T) {
	p := rbHealthy(4)
	p.PlannedDelayMS = 50000
	_, fs := RBAudit(p)
	if !RBHasReason(fs, RBReasonBackoffOverflow) {
		t.Fatalf("delay over max cap must flag: %v", fs)
	}
}
