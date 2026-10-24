package main

import "testing"

func TestE69U13ClassifyBlock(t *testing.T) {
	for _, v := range E69U13Block { if E69U13Classify(v) != E69U13ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U13ClassifyWarn(t *testing.T) {
	for _, v := range E69U13Warn { if E69U13Classify(v) != E69U13ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U13ClassifyAllow(t *testing.T) {
	for _, v := range E69U13Allow { if E69U13Classify(v) != E69U13ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U13ClassifyUnknown(t *testing.T) {
	if E69U13Classify("zzz-not-in-any-e69-catalog-88") != E69U13ClassUnknown { t.Fatal("unknown") }
}
