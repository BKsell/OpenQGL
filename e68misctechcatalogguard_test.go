package main

import "testing"

func TestE68R28ClassifyBlock(t *testing.T) {
	for _, v := range E68R28Block { if E68R28Classify(v) != E68R28ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R28ClassifyWarn(t *testing.T) {
	for _, v := range E68R28Warn { if E68R28Classify(v) != E68R28ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R28ClassifyAllow(t *testing.T) {
	for _, v := range E68R28Allow { if E68R28Classify(v) != E68R28ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R28ClassifyUnknown(t *testing.T) {
	if E68R28Classify("zzz-not-in-any-e68-catalog-77") != E68R28ClassUnknown { t.Fatal("unknown") }
}
