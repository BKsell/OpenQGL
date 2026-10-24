package main

import "testing"

func TestE69T26ClassifyBlock(t *testing.T) {
	for _, v := range E69T26Block { if E69T26Classify(v) != E69T26ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T26ClassifyWarn(t *testing.T) {
	for _, v := range E69T26Warn { if E69T26Classify(v) != E69T26ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T26ClassifyAllow(t *testing.T) {
	for _, v := range E69T26Allow { if E69T26Classify(v) != E69T26ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T26ClassifyUnknown(t *testing.T) {
	if E69T26Classify("zzz-not-in-any-e69-catalog-88") != E69T26ClassUnknown { t.Fatal("unknown") }
}
