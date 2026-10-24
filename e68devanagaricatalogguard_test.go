package main

import "testing"

func TestE68R05ClassifyBlock(t *testing.T) {
	for _, v := range E68R05Block { if E68R05Classify(v) != E68R05ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R05ClassifyWarn(t *testing.T) {
	for _, v := range E68R05Warn { if E68R05Classify(v) != E68R05ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R05ClassifyAllow(t *testing.T) {
	for _, v := range E68R05Allow { if E68R05Classify(v) != E68R05ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R05ClassifyUnknown(t *testing.T) {
	if E68R05Classify("zzz-not-in-any-e68-catalog-77") != E68R05ClassUnknown { t.Fatal("unknown") }
}
