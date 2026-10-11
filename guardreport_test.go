package main

import (
	"strings"
	"testing"
)

func TestBuildStartupGuardReport(t *testing.T) {
	sum := []guardSummary{
		{Kind: "jarclass", OK: true, Detail: "jarclass clean total=3"},
		{Kind: "launch", OK: false, Detail: "launch bad argfile"},
		{Kind: "queue", OK: true, Detail: "queue ok entries=2"},
	}
	rep := BuildStartupGuardReport(sum)
	if rep.OK {
		t.Fatalf("expected blocked")
	}
	if len(rep.Blocked) != 1 || rep.Blocked[0] != "launch" {
		t.Fatalf("blocked=%v", rep.Blocked)
	}
	if len(rep.Lines) != 3 {
		t.Fatalf("lines=%d", len(rep.Lines))
	}
}

func TestFlattenAndSummarize(t *testing.T) {
	rep := startupGuardReport{OK: true, Lines: []string{"[a] ok 1", "[b] ok 2"}}
	if s := FlattenGuardReport(rep); s != "[a] ok 1\n[b] ok 2" {
		t.Fatalf("flatten wrong: %q", s)
	}
	if s := SummarizeGuardReport(rep); s != "guards ok count=2" {
		t.Fatalf("summarize wrong: %q", s)
	}
	rep2 := startupGuardReport{OK: false, Blocked: []string{"z", "a"}, Lines: []string{"x"}}
	if s := SummarizeGuardReport(rep2); s != "guards blocked=a,z" {
		t.Fatalf("blocked summarize wrong: %q", s)
	}
}

func TestMarshalGuardReportJSON(t *testing.T) {
	rep := startupGuardReport{OK: true, Lines: []string{"[a] ok 1"}}
	s := MarshalGuardReportJSON(rep)
	if !strings.Contains(s, `"ok":true`) || !strings.Contains(s, `[a] ok 1`) {
		t.Fatalf("json wrong: %q", s)
	}
	rep2 := startupGuardReport{OK: false, Blocked: []string{"launch"}, Lines: []string{"[launch] BLOCKED x"}}
	s = MarshalGuardReportJSON(rep2)
	if !strings.Contains(s, `"ok":false`) || !strings.Contains(s, `"blocked":["launch"]`) {
		t.Fatalf("json wrong: %q", s)
	}
}

func TestGuardSummariesAll(t *testing.T) {
	sum := GuardSummariesAll(
		jarClassVerdict{OK: true, Total: 1},
		launchVerdict{OK: true, Argv: []string{"a"}},
		queueVerdict{OK: true, Total: 2},
		worldVerdict{OK: true},
	)
	if len(sum) != 4 {
		t.Fatalf("summaries=%d", len(sum))
	}
	for _, s := range sum {
		if !s.OK {
			t.Fatalf("%s not ok", s.Kind)
		}
	}
}
