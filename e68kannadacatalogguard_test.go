package main

import "testing"

func TestE68R12ClassifyBlock(t *testing.T) {
	for _, v := range E68R12Block { if E68R12Classify(v) != E68R12ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R12ClassifyWarn(t *testing.T) {
	for _, v := range E68R12Warn { if E68R12Classify(v) != E68R12ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R12ClassifyAllow(t *testing.T) {
	for _, v := range E68R12Allow { if E68R12Classify(v) != E68R12ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R12ClassifyUnknown(t *testing.T) {
	if E68R12Classify("zzz-not-in-any-e68-catalog-77") != E68R12ClassUnknown { t.Fatal("unknown") }
}
