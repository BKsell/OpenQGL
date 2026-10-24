package main

import "testing"

func TestE68R10ClassifyBlock(t *testing.T) {
	for _, v := range E68R10Block { if E68R10Classify(v) != E68R10ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R10ClassifyWarn(t *testing.T) {
	for _, v := range E68R10Warn { if E68R10Classify(v) != E68R10ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R10ClassifyAllow(t *testing.T) {
	for _, v := range E68R10Allow { if E68R10Classify(v) != E68R10ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R10ClassifyUnknown(t *testing.T) {
	if E68R10Classify("zzz-not-in-any-e68-catalog-77") != E68R10ClassUnknown { t.Fatal("unknown") }
}
