package main

import "testing"

func TestE68R08ClassifyBlock(t *testing.T) {
	for _, v := range E68R08Block { if E68R08Classify(v) != E68R08ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R08ClassifyWarn(t *testing.T) {
	for _, v := range E68R08Warn { if E68R08Classify(v) != E68R08ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R08ClassifyAllow(t *testing.T) {
	for _, v := range E68R08Allow { if E68R08Classify(v) != E68R08ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R08ClassifyUnknown(t *testing.T) {
	if E68R08Classify("zzz-not-in-any-e68-catalog-77") != E68R08ClassUnknown { t.Fatal("unknown") }
}
