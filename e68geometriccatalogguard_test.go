package main

import "testing"

func TestE68R33ClassifyBlock(t *testing.T) {
	for _, v := range E68R33Block { if E68R33Classify(v) != E68R33ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R33ClassifyWarn(t *testing.T) {
	for _, v := range E68R33Warn { if E68R33Classify(v) != E68R33ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R33ClassifyAllow(t *testing.T) {
	for _, v := range E68R33Allow { if E68R33Classify(v) != E68R33ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R33ClassifyUnknown(t *testing.T) {
	if E68R33Classify("zzz-not-in-any-e68-catalog-77") != E68R33ClassUnknown { t.Fatal("unknown") }
}
