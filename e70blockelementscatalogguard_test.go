package main

import "testing"

func TestE70T46ClassifyBlock(t *testing.T) {
	for _, v := range E70T46Block { if E70T46Classify(v) != E70T46ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T46ClassifyWarn(t *testing.T) {
	for _, v := range E70T46Warn { if E70T46Classify(v) != E70T46ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T46ClassifyAllow(t *testing.T) {
	for _, v := range E70T46Allow { if E70T46Classify(v) != E70T46ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T46ClassifyUnknown(t *testing.T) {
	if E70T46Classify("zzz-not-in-any-e70-catalog-99") != E70T46ClassUnknown { t.Fatal("unknown") }
}
