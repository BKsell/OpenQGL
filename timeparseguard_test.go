package main

import "testing"

func TestTPSecondsOK(t *testing.T) {
	safe, sec, isMs, _ := TPAuditEpoch(1_700_000_000, false)
	if !safe || isMs || sec != 1_700_000_000 {
		t.Fatalf("plain seconds should pass unchanged: safe=%v sec=%d ms=%v", safe, sec, isMs)
	}
}

func TestTPMillisHint(t *testing.T) {
	safe, sec, isMs, _ := TPAuditEpoch(1_700_000_000_000, true)
	if !safe || !isMs || sec != 1_700_000_000 {
		t.Fatalf("explicit millis should convert: safe=%v sec=%d ms=%v", safe, sec, isMs)
	}
}

func TestTPMillisAutoDetect(t *testing.T) {
	safe, _, isMs, fs := TPAuditEpoch(1_700_000_000_000, false)
	if !isMs {
		t.Fatal("bare millis-scale value must be auto-detected as millis")
	}
	if safe || !TPHasReason(fs, TPReasonUnitAmbiguous) {
		t.Fatalf("ambiguous unit must flag: safe=%v %v", safe, fs)
	}
}

func TestTPNegative(t *testing.T) {
	_, _, _, fs := TPAuditEpoch(-1, false)
	if !TPHasReason(fs, TPReasonNegativeEpoch) {
		t.Fatalf("negative epoch must flag: %v", fs)
	}
}

func TestTPOUTOfRange(t *testing.T) {
	_, _, _, fs := TPAuditEpoch(9_000_000_000, false) // ~2255 年
	if !TPHasReason(fs, TPReasonOutOfRange) {
		t.Fatalf("far-future epoch must flag: %v", fs)
	}
}

func TestTPCalendarValid(t *testing.T) {
	if safe, _ := TPAuditCalendarDate(2024, 2, 29); !safe {
		t.Fatal("2024-02-29 is a real leap day")
	}
}

func TestTPCalendarInvalidLeap(t *testing.T) {
	_, fs := TPAuditCalendarDate(2023, 2, 29)
	if !TPHasReason(fs, TPReasonInvalidCalendar) {
		t.Fatalf("2023-02-29 must be invalid: %v", fs)
	}
}

func TestTPCalendarInvalidMonth(t *testing.T) {
	_, fs := TPAuditCalendarDate(2024, 13, 1)
	if !TPHasReason(fs, TPReasonInvalidCalendar) {
		t.Fatalf("month 13 must be invalid: %v", fs)
	}
}

func TestTPCalendar30DayMonth(t *testing.T) {
	_, fs := TPAuditCalendarDate(2024, 4, 31)
	if !TPHasReason(fs, TPReasonInvalidCalendar) {
		t.Fatalf("April has no 31st: %v", fs)
	}
}

func TestTPRFC3339Zoned(t *testing.T) {
	if safe, _ := TPAuditRFC3339("2024-05-01T12:00:00Z"); !safe {
		t.Fatal("Z-suffixed timestamp is zoned")
	}
	if safe, _ := TPAuditRFC3339("2024-05-01T12:00:00+08:00"); !safe {
		t.Fatal("offset-suffixed timestamp is zoned")
	}
}

func TestTPRFC3339Naive(t *testing.T) {
	_, fs := TPAuditRFC3339("2024-05-01T12:00:00")
	if !TPHasReason(fs, TPReasonMissingTimezone) {
		t.Fatalf("datetime without timezone must flag: %v", fs)
	}
}
