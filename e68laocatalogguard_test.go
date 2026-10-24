package main

import "testing"

func TestE68R16ClassifyBlock(t *testing.T) {
	for _, v := range E68R16Block { if E68R16Classify(v) != E68R16ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R16ClassifyWarn(t *testing.T) {
	for _, v := range E68R16Warn { if E68R16Classify(v) != E68R16ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R16ClassifyAllow(t *testing.T) {
	for _, v := range E68R16Allow { if E68R16Classify(v) != E68R16ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R16ClassifyUnknown(t *testing.T) {
	if E68R16Classify("zzz-not-in-any-e68-catalog-77") != E68R16ClassUnknown { t.Fatal("unknown") }
}
