package main

import "testing"

func TestE68R30ClassifyBlock(t *testing.T) {
	for _, v := range E68R30Block { if E68R30Classify(v) != E68R30ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R30ClassifyWarn(t *testing.T) {
	for _, v := range E68R30Warn { if E68R30Classify(v) != E68R30ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R30ClassifyAllow(t *testing.T) {
	for _, v := range E68R30Allow { if E68R30Classify(v) != E68R30ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R30ClassifyUnknown(t *testing.T) {
	if E68R30Classify("zzz-not-in-any-e68-catalog-77") != E68R30ClassUnknown { t.Fatal("unknown") }
}
