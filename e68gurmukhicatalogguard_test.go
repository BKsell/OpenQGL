package main

import "testing"

func TestE68R07ClassifyBlock(t *testing.T) {
	for _, v := range E68R07Block { if E68R07Classify(v) != E68R07ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R07ClassifyWarn(t *testing.T) {
	for _, v := range E68R07Warn { if E68R07Classify(v) != E68R07ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R07ClassifyAllow(t *testing.T) {
	for _, v := range E68R07Allow { if E68R07Classify(v) != E68R07ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R07ClassifyUnknown(t *testing.T) {
	if E68R07Classify("zzz-not-in-any-e68-catalog-77") != E68R07ClassUnknown { t.Fatal("unknown") }
}
