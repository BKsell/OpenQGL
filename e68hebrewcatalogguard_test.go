package main

import "testing"

func TestE68R01ClassifyBlock(t *testing.T) {
	for _, v := range E68R01Block { if E68R01Classify(v) != E68R01ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R01ClassifyWarn(t *testing.T) {
	for _, v := range E68R01Warn { if E68R01Classify(v) != E68R01ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R01ClassifyAllow(t *testing.T) {
	for _, v := range E68R01Allow { if E68R01Classify(v) != E68R01ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R01ClassifyUnknown(t *testing.T) {
	if E68R01Classify("zzz-not-in-any-e68-catalog-77") != E68R01ClassUnknown { t.Fatal("unknown") }
}
