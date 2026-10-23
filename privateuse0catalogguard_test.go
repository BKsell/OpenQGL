package main

import "testing"

func TestPU0ClassifyBlock(t *testing.T) {
	for _, v := range PU0Block { if PU0Classify(v) != PU0ClassBlock { t.Fatalf("%s block", v) } }
}

func TestPU0ClassifyWarn(t *testing.T) {
	for _, v := range PU0Warn { if PU0Classify(v) != PU0ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPU0ClassifyAllow(t *testing.T) {
	for _, v := range PU0Allow { if PU0Classify(v) != PU0ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPU0ClassifyUnknown(t *testing.T) {
	if PU0Classify("zzz-not-in-any-catalog-11") != PU0ClassUnknown { t.Fatal("unknown") }
}
