package main

import "testing"

func TestE68O03ClassifyBlock(t *testing.T) {
	for _, v := range E68O03Block { if E68O03Classify(v) != E68O03ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68O03ClassifyWarn(t *testing.T) {
	for _, v := range E68O03Warn { if E68O03Classify(v) != E68O03ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68O03ClassifyAllow(t *testing.T) {
	for _, v := range E68O03Allow { if E68O03Classify(v) != E68O03ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68O03ClassifyUnknown(t *testing.T) {
	if E68O03Classify("zzz-not-in-any-e68-catalog-77") != E68O03ClassUnknown { t.Fatal("unknown") }
}
