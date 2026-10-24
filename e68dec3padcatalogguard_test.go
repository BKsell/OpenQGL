package main

import "testing"

func TestE68D03ClassifyBlock(t *testing.T) {
	for _, v := range E68D03Block { if E68D03Classify(v) != E68D03ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68D03ClassifyWarn(t *testing.T) {
	for _, v := range E68D03Warn { if E68D03Classify(v) != E68D03ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68D03ClassifyAllow(t *testing.T) {
	for _, v := range E68D03Allow { if E68D03Classify(v) != E68D03ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68D03ClassifyUnknown(t *testing.T) {
	if E68D03Classify("zzz-not-in-any-e68-catalog-77") != E68D03ClassUnknown { t.Fatal("unknown") }
}
