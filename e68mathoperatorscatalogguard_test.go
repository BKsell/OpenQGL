package main

import "testing"

func TestE68R27ClassifyBlock(t *testing.T) {
	for _, v := range E68R27Block { if E68R27Classify(v) != E68R27ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R27ClassifyWarn(t *testing.T) {
	for _, v := range E68R27Warn { if E68R27Classify(v) != E68R27ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R27ClassifyAllow(t *testing.T) {
	for _, v := range E68R27Allow { if E68R27Classify(v) != E68R27ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R27ClassifyUnknown(t *testing.T) {
	if E68R27Classify("zzz-not-in-any-e68-catalog-77") != E68R27ClassUnknown { t.Fatal("unknown") }
}
