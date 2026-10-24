package main

import "testing"

func TestE68R29ClassifyBlock(t *testing.T) {
	for _, v := range E68R29Block { if E68R29Classify(v) != E68R29ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R29ClassifyWarn(t *testing.T) {
	for _, v := range E68R29Warn { if E68R29Classify(v) != E68R29ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R29ClassifyAllow(t *testing.T) {
	for _, v := range E68R29Allow { if E68R29Classify(v) != E68R29ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R29ClassifyUnknown(t *testing.T) {
	if E68R29Classify("zzz-not-in-any-e68-catalog-77") != E68R29ClassUnknown { t.Fatal("unknown") }
}
