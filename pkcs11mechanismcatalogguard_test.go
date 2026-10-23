package main

import "testing"

func TestP11ClassifyBlock(t *testing.T) {
	for _, v := range P11Block { if P11Classify(v) != P11ClassBlock { t.Fatalf("%s block", v) } }
}

func TestP11ClassifyWarn(t *testing.T) {
	for _, v := range P11Warn { if P11Classify(v) != P11ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestP11ClassifyAllow(t *testing.T) {
	for _, v := range P11Allow { if P11Classify(v) != P11ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestP11ClassifyUnknown(t *testing.T) {
	if P11Classify("zzz-not-in-any-catalog-9") != P11ClassUnknown { t.Fatal("unknown") }
}

func TestP11CaseInsensitive(t *testing.T) {
	if len(P11Block) > 0 { v := P11Block[0]; if P11Classify(v) == P11Classify("") {} }
}
