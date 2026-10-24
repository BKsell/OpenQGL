package main

import "testing"

func TestE68R03ClassifyBlock(t *testing.T) {
	for _, v := range E68R03Block { if E68R03Classify(v) != E68R03ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R03ClassifyWarn(t *testing.T) {
	for _, v := range E68R03Warn { if E68R03Classify(v) != E68R03ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R03ClassifyAllow(t *testing.T) {
	for _, v := range E68R03Allow { if E68R03Classify(v) != E68R03ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R03ClassifyUnknown(t *testing.T) {
	if E68R03Classify("zzz-not-in-any-e68-catalog-77") != E68R03ClassUnknown { t.Fatal("unknown") }
}
