package main

import "testing"

func TestE68R13ClassifyBlock(t *testing.T) {
	for _, v := range E68R13Block { if E68R13Classify(v) != E68R13ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R13ClassifyWarn(t *testing.T) {
	for _, v := range E68R13Warn { if E68R13Classify(v) != E68R13ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R13ClassifyAllow(t *testing.T) {
	for _, v := range E68R13Allow { if E68R13Classify(v) != E68R13ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R13ClassifyUnknown(t *testing.T) {
	if E68R13Classify("zzz-not-in-any-e68-catalog-77") != E68R13ClassUnknown { t.Fatal("unknown") }
}
