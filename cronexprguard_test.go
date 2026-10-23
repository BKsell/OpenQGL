package main

import "testing"

func TestCRValidDaily(t *testing.T) {
	if safe, _ := CRAudit("0 9 * * *"); !safe {
		t.Fatal("daily 9am cron should pass")
	}
}

func TestCRValidNamed(t *testing.T) {
	if safe, _ := CRAudit("0 9 * * MON-FRI"); !safe {
		t.Fatal("weekday range with names should pass")
	}
}

func TestCRFieldCount(t *testing.T) {
	_, fs := CRAudit("0 9 * *")
	if !CRHasReason(fs, CRReasonFieldCount) {
		t.Fatalf("four fields must flag: %v", fs)
	}
}

func TestCROutOfRangeMinute(t *testing.T) {
	_, fs := CRAudit("60 9 * * *")
	if !CRHasReason(fs, CRReasonValueOutOfRange) {
		t.Fatalf("minute 60 must flag: %v", fs)
	}
}

func TestCROutOfRangeHour(t *testing.T) {
	_, fs := CRAudit("0 24 * * *")
	if !CRHasReason(fs, CRReasonValueOutOfRange) {
		t.Fatalf("hour 24 must flag: %v", fs)
	}
}

func TestCRStepZero(t *testing.T) {
	_, fs := CRAudit("*/0 * * * *")
	if !CRHasReason(fs, CRReasonStepZero) {
		t.Fatalf("step /0 must flag: %v", fs)
	}
}

func TestCRInvertedRange(t *testing.T) {
	_, fs := CRAudit("30-10 * * * *")
	if !CRHasReason(fs, CRReasonValueOutOfRange) {
		t.Fatalf("inverted range must flag: %v", fs)
	}
}

func TestCREmptyListItem(t *testing.T) {
	_, fs := CRAudit("1,,3 * * * *")
	if !CRHasReason(fs, CRReasonEmptyListItem) {
		t.Fatalf("empty list item must flag: %v", fs)
	}
}

func TestCRUnknownName(t *testing.T) {
	_, fs := CRAudit("0 9 * * FOO")
	if !CRHasReason(fs, CRReasonUnknownName) {
		t.Fatalf("unknown weekday name must flag: %v", fs)
	}
}

func TestCRShellMetachar(t *testing.T) {
	_, fs := CRAudit("0 9 * * *; rm -rf /")
	if !CRHasReason(fs, CRReasonShellInjection) {
		t.Fatalf("shell metacharacter in cron must flag: %v", fs)
	}
}

func TestCRValidMonthName(t *testing.T) {
	if safe, _ := CRAudit("0 9 1 JAN-JUN *"); !safe {
		t.Fatal("month name range should pass")
	}
}
