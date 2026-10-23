package main

import (
	"strings"
	"testing"
)

func TestLPNormal(t *testing.T) {
	r := LPAudit(`C:\instances\myworld\level.dat`)
	if !r.Safe {
		t.Fatalf("normal path should be safe: %v", r.Findings)
	}
}

func TestLPExceedsMaxPath(t *testing.T) {
	long := `C:\` + strings.Repeat("a", 270)
	r := LPAudit(long)
	if !r.HasReason(LPReasonExceedsMaxPath) {
		t.Fatalf("want max path exceeded: %v", r.Findings)
	}
}

func TestLPShortName83(t *testing.T) {
	r := LPAudit(`C:\PROGRA~1\Java\bin\java.exe`)
	if !r.HasReason(LPReasonShortName83) {
		t.Fatalf("want 8.3 short name: %v", r.Findings)
	}
}

func TestLPShortNameNoTilde(t *testing.T) {
	// 普通大写短词不是 8.3（无波浪号数字）
	r := LPAudit(`C:\Java\bin`)
	if r.HasReason(LPReasonShortName83) {
		t.Fatalf("normal uppercase wrongly flagged: %v", r.Findings)
	}
}

func TestLPTrailingDot(t *testing.T) {
	r := LPAudit(`instance\evil.jar.`)
	if !r.HasReason(LPReasonTrailingDotSpace) {
		t.Fatalf("want trailing dot: %v", r.Findings)
	}
}

func TestLPTrailingSpace(t *testing.T) {
	r := LPAudit(`instance\evil.jar `)
	if !r.HasReason(LPReasonTrailingDotSpace) {
		t.Fatalf("want trailing space: %v", r.Findings)
	}
}

func TestLPLeadingSpace(t *testing.T) {
	r := LPAudit(`instance\ evil.jar`)
	if !r.HasReason(LPReasonLeadingDotSpace) {
		t.Fatalf("want leading space: %v", r.Findings)
	}
}

func TestLPDotDotComponent(t *testing.T) {
	r := LPAudit(`instance\..\other\f`)
	if !r.HasReason(LPReasonDotsComponent) {
		t.Fatalf("want dotdot component: %v", r.Findings)
	}
}

func TestLPEmptyComponentDoubleSlash(t *testing.T) {
	r := LPAudit(`C:\instances\\evil`)
	if !r.HasReason(LPReasonEmptyComponent) {
		t.Fatalf("want empty component: %v", r.Findings)
	}
}

func TestLPMultibyteByteLen(t *testing.T) {
	// 中文字符 UTF-8 3 字节：构造字符数不超但字节超 260 的路径
	// 80 个中文字 = 240 字节 + 前缀
	name := strings.Repeat("界", 85)
	r := LPAudit(`C:\` + name)
	if !r.HasReason(LPReasonExceedsMaxPath) {
		t.Fatalf("multibyte path should exceed by bytes: %v", r.Findings)
	}
}

func TestLPForwardSlash(t *testing.T) {
	r := LPAudit("C:/instances/world/level.dat")
	if !r.Safe {
		t.Fatalf("forward slash normal path should be safe: %v", r.Findings)
	}
}

func TestLPComponentTooLong(t *testing.T) {
	r := LPAudit(`C:\inst\` + strings.Repeat("x", 256))
	if !r.HasReason(LPReasonExceedsSafeLimit) {
		t.Fatalf("want component too long: %v", r.Findings)
	}
}

func TestLPDrivePrefixStripped(t *testing.T) {
	// 盘符分量不应被当作 8.3 或空
	r := LPAudit(`D:\a\b.jar`)
	for _, f := range r.Findings {
		if f.Comp == "D:" {
			t.Fatalf("drive prefix should be stripped: %v", f)
		}
	}
}

func TestLPShortNameExt(t *testing.T) {
	r := LPAudit(`SECRET~1.TXT`)
	if !r.HasReason(LPReasonShortName83) {
		t.Fatalf("want secret~1.txt flagged: %v", r.Findings)
	}
}
