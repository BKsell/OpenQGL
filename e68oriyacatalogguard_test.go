package main

import "testing"

func TestE68R09ClassifyBlock(t *testing.T) {
	for _, v := range E68R09Block { if E68R09Classify(v) != E68R09ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R09ClassifyWarn(t *testing.T) {
	for _, v := range E68R09Warn { if E68R09Classify(v) != E68R09ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R09ClassifyAllow(t *testing.T) {
	for _, v := range E68R09Allow { if E68R09Classify(v) != E68R09ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R09ClassifyUnknown(t *testing.T) {
	if E68R09Classify("zzz-not-in-any-e68-catalog-77") != E68R09ClassUnknown { t.Fatal("unknown") }
}
