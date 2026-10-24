package main

import "testing"

func TestE68S01ClassifyBlock(t *testing.T) {
	for _, v := range E68S01Block { if E68S01Classify(v) != E68S01ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68S01ClassifyWarn(t *testing.T) {
	for _, v := range E68S01Warn { if E68S01Classify(v) != E68S01ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68S01ClassifyAllow(t *testing.T) {
	for _, v := range E68S01Allow { if E68S01Classify(v) != E68S01ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68S01ClassifyUnknown(t *testing.T) {
	if E68S01Classify("zzz-not-in-any-e68-catalog-77") != E68S01ClassUnknown { t.Fatal("unknown") }
}
