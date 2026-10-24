package main

import "testing"

func TestE68R23ClassifyBlock(t *testing.T) {
	for _, v := range E68R23Block { if E68R23Classify(v) != E68R23ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R23ClassifyWarn(t *testing.T) {
	for _, v := range E68R23Warn { if E68R23Classify(v) != E68R23ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R23ClassifyAllow(t *testing.T) {
	for _, v := range E68R23Allow { if E68R23Classify(v) != E68R23ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R23ClassifyUnknown(t *testing.T) {
	if E68R23Classify("zzz-not-in-any-e68-catalog-77") != E68R23ClassUnknown { t.Fatal("unknown") }
}
