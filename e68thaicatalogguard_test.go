package main

import "testing"

func TestE68R15ClassifyBlock(t *testing.T) {
	for _, v := range E68R15Block { if E68R15Classify(v) != E68R15ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R15ClassifyWarn(t *testing.T) {
	for _, v := range E68R15Warn { if E68R15Classify(v) != E68R15ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R15ClassifyAllow(t *testing.T) {
	for _, v := range E68R15Allow { if E68R15Classify(v) != E68R15ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R15ClassifyUnknown(t *testing.T) {
	if E68R15Classify("zzz-not-in-any-e68-catalog-77") != E68R15ClassUnknown { t.Fatal("unknown") }
}
