package main

import "testing"

func trcHasReason(fs []TRCFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestTRCSafeUsage(t *testing.T) {
	u := TRCSafeUsage(`C:\Users\贝壳\AppData\Local\Temp\openqgl283749102\dl.jar`)
	if f := TRCEvaluate(u, DefaultTRCPolicy()); len(f) != 0 {
		t.Fatalf("safe usage must pass: %v", f)
	}
}

func TestTRCPredictableName(t *testing.T) {
	pol := DefaultTRCPolicy()
	u := TRCFileUsage{Path: "/tmp/tmp", Mode: 0o600}
	if f := TRCEvaluate(u, pol); !trcHasReason(f, TRCReasonPredictableName) {
		t.Fatal("fixed name /tmp/tmp must be flagged")
	}
}

func TestTRCSharedDirNonExclusive(t *testing.T) {
	pol := DefaultTRCPolicy()
	u := TRCFileUsage{
		Path:               "/tmp/dl-12345678",
		NameUnpredictable:  true,
		RandomSuffixLen:    8,
		InWorldWritableDir: true,
		Mode:               0o600,
	}
	f := TRCEvaluate(u, pol)
	if !trcHasReason(f, TRCReasonMissingExclusive) {
		t.Fatal("shared temp dir without O_EXCL must be flagged")
	}
}

func TestTRCSymlinkFollow(t *testing.T) {
	pol := DefaultTRCPolicy()
	u := TRCSafeUsage("/tmp/x-abcdef12")
	u.UsedNoFollow = false
	if f := TRCEvaluate(u, pol); !trcHasReason(f, TRCReasonSymlinkFollowed) {
		t.Fatal("following symlinks must be flagged")
	}
}

func TestTRCTOCTOU(t *testing.T) {
	pol := DefaultTRCPolicy()
	u := TRCSafeUsage("/tmp/x-abcdef12")
	u.DidStatBeforeOpen = true
	if f := TRCEvaluate(u, pol); !trcHasReason(f, TRCReasonTOCTOUStatThenOpen) {
		t.Fatal("stat-then-open must be flagged")
	}
}

func TestTRCModeOpen(t *testing.T) {
	pol := DefaultTRCPolicy()
	u := TRCSafeUsage("/tmp/x-abcdef12")
	u.Mode = 0o666
	if f := TRCEvaluate(u, pol); !trcHasReason(f, TRCReasonModeTooOpen) {
		t.Fatal("0666 temp file must be flagged")
	}
}

func TestTRCWeakRandomness(t *testing.T) {
	pol := DefaultTRCPolicy()
	u := TRCSafeUsage("/tmp/x-abcd")
	u.RandomSuffixLen = 4
	if f := TRCEvaluate(u, pol); !trcHasReason(f, TRCReasonBadRandomEntropy) {
		t.Fatal("short random suffix must be flagged")
	}
}

func TestTRCRenameTarget(t *testing.T) {
	pol := DefaultTRCPolicy()
	u := TRCSafeUsage("/tmp/x-abcdef12")
	u.WillRename = true
	u.RenameTargetValidated = false
	if f := TRCEvaluate(u, pol); !trcHasReason(f, TRCReasonUnsafeRenameTarget) {
		t.Fatal("rename without target validation must be flagged")
	}
}
