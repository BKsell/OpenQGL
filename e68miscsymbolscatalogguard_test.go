package main

import "testing"

func TestE68R34ClassifyBlock(t *testing.T) {
	for _, v := range E68R34Block { if E68R34Classify(v) != E68R34ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R34ClassifyWarn(t *testing.T) {
	for _, v := range E68R34Warn { if E68R34Classify(v) != E68R34ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R34ClassifyAllow(t *testing.T) {
	for _, v := range E68R34Allow { if E68R34Classify(v) != E68R34ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R34ClassifyUnknown(t *testing.T) {
	if E68R34Classify("zzz-not-in-any-e68-catalog-77") != E68R34ClassUnknown { t.Fatal("unknown") }
}
