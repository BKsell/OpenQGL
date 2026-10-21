package main

import "testing"

func TestParseContentRange(t *testing.T) {
	cr, err := ParseContentRange("bytes 100-199/1000")
	if err != nil || cr.Start != 100 || cr.End != 199 || cr.Total != 1000 {
		t.Fatalf("parse ok case failed: %+v err=%v", cr, err)
	}
	cr, err = ParseContentRange("bytes 200-299/*")
	if err != nil || cr.Start != 200 || cr.End != 299 || cr.Total != -1 {
		t.Fatalf("open-ended total parse failed: %+v err=%v", cr, err)
	}
	for _, bad := range []string{
		"", "bytes ", "100-199/1000", "bytes 100/1000",
		"bytes abc-199/1000", "bytes 300-100/1000", "bytes 100-199/x",
	} {
		if _, err := ParseContentRange(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestParseRangeRequest(t *testing.T) {
	s, e, err := ParseRangeRequest("bytes=500-")
	if err != nil || s != 500 || e != -1 {
		t.Fatalf("open range: %d %d %v", s, e, err)
	}
	s, e, err = ParseRangeRequest("bytes=0-999")
	if err != nil || s != 0 || e != 999 {
		t.Fatalf("closed range: %d %d %v", s, e, err)
	}
	for _, bad := range []string{"bytes=0-1,2-3", "items=0-9", "bytes=-", "bytes=9-1"} {
		if _, _, err := ParseRangeRequest(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestResumeFirstFull200(t *testing.T) {
	lim := defaultResumeLimits()
	s := &ResumeSession{Total: -1}
	d := s.JudgeSegment(200, 0, -1, ContentRange{}, 4096, `"v1"`, "", 4096, lim)
	if !d.Accept || d.WriteOffset != 0 || !s.GotFull || s.Total != 4096 || !s.IsComplete() {
		t.Fatalf("first 200 decision wrong: %+v session=%+v", d, s)
	}
}

func TestResumeFull200TooLarge(t *testing.T) {
	lim := defaultResumeLimits()
	s := &ResumeSession{Total: -1}
	big := lim.MaxTotalBytes + 1
	d := s.JudgeSegment(200, 0, -1, ContentRange{}, big, "", "", big, lim)
	if d.Accept || d.Reason != errResumeTotalTooLarge {
		t.Fatalf("expected total too large, got %+v", d)
	}
}

func TestResumeSequential206(t *testing.T) {
	lim := defaultResumeLimits()
	s := &ResumeSession{Total: 1000}
	s.ETag = `"v1"`
	// 第一片 0-499。
	d := s.JudgeSegment(206, 0, 499, ContentRange{Start: 0, End: 499, Total: 1000}, 500, `"v1"`, "", -1, lim)
	if !d.Accept || d.WriteOffset != 0 || s.Written != 500 {
		t.Fatalf("first 206: %+v", d)
	}
	// 第二片 500-999。
	d = s.JudgeSegment(206, 500, 999, ContentRange{Start: 500, End: 999, Total: 1000}, 500, `"v1"`, "", -1, lim)
	if !d.Accept || s.Written != 1000 || !s.IsComplete() {
		t.Fatalf("second 206: %+v complete=%v", d, s.IsComplete())
	}
}

func TestResumeETagSwapRejected(t *testing.T) {
	lim := defaultResumeLimits()
	s := &ResumeSession{Total: 1000, ETag: `"v1"`, UsedResume: true, Written: 500, Segments: 1}
	d := s.JudgeSegment(206, 500, 999, ContentRange{Start: 500, End: 999, Total: 1000}, 500, `"v2"`, "", -1, lim)
	if d.Accept || !d.RestartFresh || d.Reason != errResumeValidatorGone {
		t.Fatalf("etag swap must force restart: %+v", d)
	}
}

func TestResumeWeakETagNotStrong(t *testing.T) {
	if v := normalizeValidator(`W/"v1"`); v != "" {
		t.Fatalf("weak etag must normalize to empty, got %q", v)
	}
	if v := normalizeValidator(`"v1"`); v != `"v1"` {
		t.Fatalf("strong etag got %q", v)
	}
}

func TestResumeTotalChanged(t *testing.T) {
	lim := defaultResumeLimits()
	s := &ResumeSession{Total: 1000, ETag: `"v1"`, UsedResume: true, Written: 500, Segments: 1}
	d := s.JudgeSegment(206, 500, 999, ContentRange{Start: 500, End: 999, Total: 1200}, 500, `"v1"`, "", -1, lim)
	if d.Accept || d.Reason != errResumeTotalChanged {
		t.Fatalf("total change must reject: %+v", d)
	}
}

func TestResumeOverlapAndGap(t *testing.T) {
	lim := defaultResumeLimits()
	s := &ResumeSession{Total: 1000, ETag: `"v1"`, UsedResume: true, Written: 500, Segments: 1}
	// 回退/重叠。
	d := s.JudgeSegment(206, 400, 499, ContentRange{Start: 400, End: 499, Total: 1000}, 100, `"v1"`, "", -1, lim)
	if d.Accept || d.Reason != errResumeOverlap {
		t.Fatalf("overlap: %+v", d)
	}
	// 留缝。
	d = s.JudgeSegment(206, 600, 699, ContentRange{Start: 600, End: 699, Total: 1000}, 100, `"v1"`, "", -1, lim)
	if d.Accept || d.Reason != errResumeGap {
		t.Fatalf("gap: %+v", d)
	}
}

func TestResumeBodyLengthMismatch(t *testing.T) {
	lim := defaultResumeLimits()
	s := &ResumeSession{Total: 1000, ETag: `"v1"`}
	// 声明 0-499 但只收到 400 字节。
	d := s.JudgeSegment(206, 0, 499, ContentRange{Start: 0, End: 499, Total: 1000}, 400, `"v1"`, "", -1, lim)
	if d.Accept || d.Reason != errResumeRangeMismatch {
		t.Fatalf("body length mismatch: %+v", d)
	}
}

func TestResume200After206ForcesRestart(t *testing.T) {
	lim := defaultResumeLimits()
	s := &ResumeSession{Total: 1000, ETag: `"v1"`, UsedResume: true, Written: 500, Segments: 1}
	d := s.JudgeSegment(200, 0, -1, ContentRange{}, 1000, `"v1"`, "", 1000, lim)
	if d.Accept || !d.RestartFresh || d.Reason != errResumeStatusMismatch {
		t.Fatalf("200 after 206 must force fresh restart: %+v", d)
	}
}

func TestResumeUnsupportedStatus(t *testing.T) {
	s := &ResumeSession{Total: -1}
	d := s.JudgeSegment(416, 0, -1, ContentRange{}, 0, "", "", -1, defaultResumeLimits())
	if d.Accept {
		t.Fatalf("416 must not be accepted")
	}
}

func TestResumeEndBeyondTotal(t *testing.T) {
	lim := defaultResumeLimits()
	s := &ResumeSession{Total: 1000, ETag: `"v1"`}
	d := s.JudgeSegment(206, 0, 999, ContentRange{Start: 0, End: 1000, Total: 1000}, 1001, `"v1"`, "", -1, lim)
	if d.Accept || d.Reason != errResumeRangeMismatch {
		t.Fatalf("end beyond total: %+v", d)
	}
}

func TestResumeNextRangeValue(t *testing.T) {
	s := &ResumeSession{Written: 750}
	if s.NextRangeValue() != "bytes=750-" {
		t.Fatalf("next range wrong: %s", s.NextRangeValue())
	}
}
