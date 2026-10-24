package main

import "testing"

func TestE68R26ClassifyBlock(t *testing.T) {
	for _, v := range E68R26Block { if E68R26Classify(v) != E68R26ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R26ClassifyWarn(t *testing.T) {
	for _, v := range E68R26Warn { if E68R26Classify(v) != E68R26ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R26ClassifyAllow(t *testing.T) {
	for _, v := range E68R26Allow { if E68R26Classify(v) != E68R26ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R26ClassifyUnknown(t *testing.T) {
	if E68R26Classify("zzz-not-in-any-e68-catalog-77") != E68R26ClassUnknown { t.Fatal("unknown") }
}
