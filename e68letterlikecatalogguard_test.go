package main

import "testing"

func TestE68R24ClassifyBlock(t *testing.T) {
	for _, v := range E68R24Block { if E68R24Classify(v) != E68R24ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R24ClassifyWarn(t *testing.T) {
	for _, v := range E68R24Warn { if E68R24Classify(v) != E68R24ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R24ClassifyAllow(t *testing.T) {
	for _, v := range E68R24Allow { if E68R24Classify(v) != E68R24ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R24ClassifyUnknown(t *testing.T) {
	if E68R24Classify("zzz-not-in-any-e68-catalog-77") != E68R24ClassUnknown { t.Fatal("unknown") }
}
