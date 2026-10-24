package main

import "testing"

func TestE68R19ClassifyBlock(t *testing.T) {
	for _, v := range E68R19Block { if E68R19Classify(v) != E68R19ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R19ClassifyWarn(t *testing.T) {
	for _, v := range E68R19Warn { if E68R19Classify(v) != E68R19ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R19ClassifyAllow(t *testing.T) {
	for _, v := range E68R19Allow { if E68R19Classify(v) != E68R19ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R19ClassifyUnknown(t *testing.T) {
	if E68R19Classify("zzz-not-in-any-e68-catalog-77") != E68R19ClassUnknown { t.Fatal("unknown") }
}
