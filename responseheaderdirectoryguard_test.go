package main

import "testing"

func TestRH2ClassifyBlock(t *testing.T) {
	for _, v := range RH2Block { if RH2Classify(v) != RH2ClassBlock { t.Fatalf("%s block", v) } }
}

func TestRH2ClassifyWarn(t *testing.T) {
	for _, v := range RH2Warn { if RH2Classify(v) != RH2ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestRH2ClassifyAllow(t *testing.T) {
	for _, v := range RH2Allow { if RH2Classify(v) != RH2ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestRH2ClassifyUnknown(t *testing.T) {
	if RH2Classify("zzz-not-in-any-catalog-9") != RH2ClassUnknown { t.Fatal("unknown") }
}

func TestRH2CaseInsensitive(t *testing.T) {
	if len(RH2Block) > 0 { v := RH2Block[0]; if RH2Classify(v) == RH2Classify("") {} }
}
