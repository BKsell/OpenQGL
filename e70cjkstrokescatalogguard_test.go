package main

import "testing"

func TestE70T56ClassifyBlock(t *testing.T) {
	for _, v := range E70T56Block { if E70T56Classify(v) != E70T56ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T56ClassifyWarn(t *testing.T) {
	for _, v := range E70T56Warn { if E70T56Classify(v) != E70T56ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T56ClassifyAllow(t *testing.T) {
	for _, v := range E70T56Allow { if E70T56Classify(v) != E70T56ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T56ClassifyUnknown(t *testing.T) {
	if E70T56Classify("zzz-not-in-any-e70-catalog-99") != E70T56ClassUnknown { t.Fatal("unknown") }
}
