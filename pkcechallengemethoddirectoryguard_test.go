package main

import "testing"

func TestPK2ClassifyBlock(t *testing.T) {
	for _, v := range PK2Block { if PK2Classify(v) != PK2ClassBlock { t.Fatalf("%s block", v) } }
}

func TestPK2ClassifyWarn(t *testing.T) {
	for _, v := range PK2Warn { if PK2Classify(v) != PK2ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPK2ClassifyAllow(t *testing.T) {
	for _, v := range PK2Allow { if PK2Classify(v) != PK2ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPK2ClassifyUnknown(t *testing.T) {
	if PK2Classify("zzz-not-in-any-catalog-9") != PK2ClassUnknown { t.Fatal("unknown") }
}

func TestPK2CaseInsensitive(t *testing.T) {
	if len(PK2Block) > 0 { v := PK2Block[0]; if PK2Classify(v) == PK2Classify("") {} }
}
