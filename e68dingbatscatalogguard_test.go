package main

import "testing"

func TestE68R35ClassifyBlock(t *testing.T) {
	for _, v := range E68R35Block { if E68R35Classify(v) != E68R35ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R35ClassifyWarn(t *testing.T) {
	for _, v := range E68R35Warn { if E68R35Classify(v) != E68R35ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R35ClassifyAllow(t *testing.T) {
	for _, v := range E68R35Allow { if E68R35Classify(v) != E68R35ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R35ClassifyUnknown(t *testing.T) {
	if E68R35Classify("zzz-not-in-any-e68-catalog-77") != E68R35ClassUnknown { t.Fatal("unknown") }
}
