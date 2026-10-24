package main

import "testing"

func TestE68R02ClassifyBlock(t *testing.T) {
	for _, v := range E68R02Block { if E68R02Classify(v) != E68R02ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R02ClassifyWarn(t *testing.T) {
	for _, v := range E68R02Warn { if E68R02Classify(v) != E68R02ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R02ClassifyAllow(t *testing.T) {
	for _, v := range E68R02Allow { if E68R02Classify(v) != E68R02ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R02ClassifyUnknown(t *testing.T) {
	if E68R02Classify("zzz-not-in-any-e68-catalog-77") != E68R02ClassUnknown { t.Fatal("unknown") }
}
