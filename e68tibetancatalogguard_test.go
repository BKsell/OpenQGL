package main

import "testing"

func TestE68R17ClassifyBlock(t *testing.T) {
	for _, v := range E68R17Block { if E68R17Classify(v) != E68R17ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R17ClassifyWarn(t *testing.T) {
	for _, v := range E68R17Warn { if E68R17Classify(v) != E68R17ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R17ClassifyAllow(t *testing.T) {
	for _, v := range E68R17Allow { if E68R17Classify(v) != E68R17ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R17ClassifyUnknown(t *testing.T) {
	if E68R17Classify("zzz-not-in-any-e68-catalog-77") != E68R17ClassUnknown { t.Fatal("unknown") }
}
