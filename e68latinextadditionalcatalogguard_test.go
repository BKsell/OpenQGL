package main

import "testing"

func TestE68R21ClassifyBlock(t *testing.T) {
	for _, v := range E68R21Block { if E68R21Classify(v) != E68R21ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R21ClassifyWarn(t *testing.T) {
	for _, v := range E68R21Warn { if E68R21Classify(v) != E68R21ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R21ClassifyAllow(t *testing.T) {
	for _, v := range E68R21Allow { if E68R21Classify(v) != E68R21ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R21ClassifyUnknown(t *testing.T) {
	if E68R21Classify("zzz-not-in-any-e68-catalog-77") != E68R21ClassUnknown { t.Fatal("unknown") }
}
