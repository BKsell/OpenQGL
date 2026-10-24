package main

import "testing"

func TestE68R04ClassifyBlock(t *testing.T) {
	for _, v := range E68R04Block { if E68R04Classify(v) != E68R04ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R04ClassifyWarn(t *testing.T) {
	for _, v := range E68R04Warn { if E68R04Classify(v) != E68R04ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R04ClassifyAllow(t *testing.T) {
	for _, v := range E68R04Allow { if E68R04Classify(v) != E68R04ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R04ClassifyUnknown(t *testing.T) {
	if E68R04Classify("zzz-not-in-any-e68-catalog-77") != E68R04ClassUnknown { t.Fatal("unknown") }
}
