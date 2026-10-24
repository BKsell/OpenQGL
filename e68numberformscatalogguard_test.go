package main

import "testing"

func TestE68R25ClassifyBlock(t *testing.T) {
	for _, v := range E68R25Block { if E68R25Classify(v) != E68R25ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R25ClassifyWarn(t *testing.T) {
	for _, v := range E68R25Warn { if E68R25Classify(v) != E68R25ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R25ClassifyAllow(t *testing.T) {
	for _, v := range E68R25Allow { if E68R25Classify(v) != E68R25ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R25ClassifyUnknown(t *testing.T) {
	if E68R25Classify("zzz-not-in-any-e68-catalog-77") != E68R25ClassUnknown { t.Fatal("unknown") }
}
