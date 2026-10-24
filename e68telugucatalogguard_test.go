package main

import "testing"

func TestE68R11ClassifyBlock(t *testing.T) {
	for _, v := range E68R11Block { if E68R11Classify(v) != E68R11ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R11ClassifyWarn(t *testing.T) {
	for _, v := range E68R11Warn { if E68R11Classify(v) != E68R11ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R11ClassifyAllow(t *testing.T) {
	for _, v := range E68R11Allow { if E68R11Classify(v) != E68R11ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R11ClassifyUnknown(t *testing.T) {
	if E68R11Classify("zzz-not-in-any-e68-catalog-77") != E68R11ClassUnknown { t.Fatal("unknown") }
}
