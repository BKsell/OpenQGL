package main

import "testing"

func TestE68R06ClassifyBlock(t *testing.T) {
	for _, v := range E68R06Block { if E68R06Classify(v) != E68R06ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R06ClassifyWarn(t *testing.T) {
	for _, v := range E68R06Warn { if E68R06Classify(v) != E68R06ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R06ClassifyAllow(t *testing.T) {
	for _, v := range E68R06Allow { if E68R06Classify(v) != E68R06ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R06ClassifyUnknown(t *testing.T) {
	if E68R06Classify("zzz-not-in-any-e68-catalog-77") != E68R06ClassUnknown { t.Fatal("unknown") }
}
