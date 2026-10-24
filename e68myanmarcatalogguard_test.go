package main

import "testing"

func TestE68R18ClassifyBlock(t *testing.T) {
	for _, v := range E68R18Block { if E68R18Classify(v) != E68R18ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE68R18ClassifyWarn(t *testing.T) {
	for _, v := range E68R18Warn { if E68R18Classify(v) != E68R18ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE68R18ClassifyAllow(t *testing.T) {
	for _, v := range E68R18Allow { if E68R18Classify(v) != E68R18ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE68R18ClassifyUnknown(t *testing.T) {
	if E68R18Classify("zzz-not-in-any-e68-catalog-77") != E68R18ClassUnknown { t.Fatal("unknown") }
}
