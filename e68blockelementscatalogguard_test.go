package main

import "testing"

func TestE68R32ClassifyBlock(t *testing.T) {
	for _, v := range E68R32Block { if E68R32Classify(v) != E68R32ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R32ClassifyWarn(t *testing.T) {
	for _, v := range E68R32Warn { if E68R32Classify(v) != E68R32ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R32ClassifyAllow(t *testing.T) {
	for _, v := range E68R32Allow { if E68R32Classify(v) != E68R32ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R32ClassifyUnknown(t *testing.T) {
	if E68R32Classify("zzz-not-in-any-e68-catalog-77") != E68R32ClassUnknown { t.Fatal("unknown") }
}
