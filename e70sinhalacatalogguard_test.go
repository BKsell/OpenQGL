package main

import "testing"

func TestE70T18ClassifyBlock(t *testing.T) {
	for _, v := range E70T18Block { if E70T18Classify(v) != E70T18ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T18ClassifyWarn(t *testing.T) {
	for _, v := range E70T18Warn { if E70T18Classify(v) != E70T18ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T18ClassifyAllow(t *testing.T) {
	for _, v := range E70T18Allow { if E70T18Classify(v) != E70T18ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T18ClassifyUnknown(t *testing.T) {
	if E70T18Classify("zzz-not-in-any-e70-catalog-99") != E70T18ClassUnknown { t.Fatal("unknown") }
}
