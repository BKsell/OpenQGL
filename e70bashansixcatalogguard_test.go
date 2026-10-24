package main

import "testing"

func TestE70BAXClassifyBlock(t *testing.T) {
	for _, v := range E70BAXBlock { if E70BAXClassify(v) != E70BAXClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70BAXClassifyWarn(t *testing.T) {
	for _, v := range E70BAXWarn { if E70BAXClassify(v) != E70BAXClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70BAXClassifyAllow(t *testing.T) {
	for _, v := range E70BAXAllow { if E70BAXClassify(v) != E70BAXClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70BAXClassifyUnknown(t *testing.T) {
	if E70BAXClassify("zzz-not-in-any-e70-catalog-99") != E70BAXClassUnknown { t.Fatal("unknown") }
}
