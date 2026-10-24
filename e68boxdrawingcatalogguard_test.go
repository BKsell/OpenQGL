package main

import "testing"

func TestE68R31ClassifyBlock(t *testing.T) {
	for _, v := range E68R31Block { if E68R31Classify(v) != E68R31ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R31ClassifyWarn(t *testing.T) {
	for _, v := range E68R31Warn { if E68R31Classify(v) != E68R31ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R31ClassifyAllow(t *testing.T) {
	for _, v := range E68R31Allow { if E68R31Classify(v) != E68R31ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R31ClassifyUnknown(t *testing.T) {
	if E68R31Classify("zzz-not-in-any-e68-catalog-77") != E68R31ClassUnknown { t.Fatal("unknown") }
}
