package main

import "testing"

func TestE68S00ClassifyBlock(t *testing.T) {
	for _, v := range E68S00Block { if E68S00Classify(v) != E68S00ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68S00ClassifyWarn(t *testing.T) {
	for _, v := range E68S00Warn { if E68S00Classify(v) != E68S00ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68S00ClassifyAllow(t *testing.T) {
	for _, v := range E68S00Allow { if E68S00Classify(v) != E68S00ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68S00ClassifyUnknown(t *testing.T) {
	if E68S00Classify("zzz-not-in-any-e68-catalog-77") != E68S00ClassUnknown { t.Fatal("unknown") }
}
