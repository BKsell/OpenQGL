package main

import "testing"

func TestE68R14ClassifyBlock(t *testing.T) {
	for _, v := range E68R14Block { if E68R14Classify(v) != E68R14ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R14ClassifyWarn(t *testing.T) {
	for _, v := range E68R14Warn { if E68R14Classify(v) != E68R14ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R14ClassifyAllow(t *testing.T) {
	for _, v := range E68R14Allow { if E68R14Classify(v) != E68R14ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R14ClassifyUnknown(t *testing.T) {
	if E68R14Classify("zzz-not-in-any-e68-catalog-77") != E68R14ClassUnknown { t.Fatal("unknown") }
}
