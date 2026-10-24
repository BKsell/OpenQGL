package main

import "testing"

func TestE69T18ClassifyBlock(t *testing.T) {
	for _, v := range E69T18Block { if E69T18Classify(v) != E69T18ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T18ClassifyWarn(t *testing.T) {
	for _, v := range E69T18Warn { if E69T18Classify(v) != E69T18ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T18ClassifyAllow(t *testing.T) {
	for _, v := range E69T18Allow { if E69T18Classify(v) != E69T18ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T18ClassifyUnknown(t *testing.T) {
	if E69T18Classify("zzz-not-in-any-e69-catalog-88") != E69T18ClassUnknown { t.Fatal("unknown") }
}
