package main

import "testing"

func TestPU2ClassifyBlock(t *testing.T) {
	for _, v := range PU2Block { if PU2Classify(v) != PU2ClassBlock { t.Fatalf("%s block", v) } }
}

func TestPU2ClassifyWarn(t *testing.T) {
	for _, v := range PU2Warn { if PU2Classify(v) != PU2ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPU2ClassifyAllow(t *testing.T) {
	for _, v := range PU2Allow { if PU2Classify(v) != PU2ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPU2ClassifyUnknown(t *testing.T) {
	if PU2Classify("zzz-not-in-any-catalog-11") != PU2ClassUnknown { t.Fatal("unknown") }
}
