package main

import "testing"

func TestE68R22ClassifyBlock(t *testing.T) {
	for _, v := range E68R22Block { if E68R22Classify(v) != E68R22ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R22ClassifyWarn(t *testing.T) {
	for _, v := range E68R22Warn { if E68R22Classify(v) != E68R22ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R22ClassifyAllow(t *testing.T) {
	for _, v := range E68R22Allow { if E68R22Classify(v) != E68R22ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R22ClassifyUnknown(t *testing.T) {
	if E68R22Classify("zzz-not-in-any-e68-catalog-77") != E68R22ClassUnknown { t.Fatal("unknown") }
}
