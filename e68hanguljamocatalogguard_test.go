package main

import "testing"

func TestE68R20ClassifyBlock(t *testing.T) {
	for _, v := range E68R20Block { if E68R20Classify(v) != E68R20ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R20ClassifyWarn(t *testing.T) {
	for _, v := range E68R20Warn { if E68R20Classify(v) != E68R20ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R20ClassifyAllow(t *testing.T) {
	for _, v := range E68R20Allow { if E68R20Classify(v) != E68R20ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R20ClassifyUnknown(t *testing.T) {
	if E68R20Classify("zzz-not-in-any-e68-catalog-77") != E68R20ClassUnknown { t.Fatal("unknown") }
}
