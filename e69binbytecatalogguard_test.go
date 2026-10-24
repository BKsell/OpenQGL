package main

import "testing"

func TestE69BINClassifyBlock(t *testing.T) {
	for _, v := range E69BINBlock { if E69BINClassify(v) != E69BINClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69BINClassifyWarn(t *testing.T) {
	for _, v := range E69BINWarn { if E69BINClassify(v) != E69BINClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69BINClassifyAllow(t *testing.T) {
	for _, v := range E69BINAllow { if E69BINClassify(v) != E69BINClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69BINClassifyUnknown(t *testing.T) {
	if E69BINClassify("zzz-not-in-any-e69-catalog-88") != E69BINClassUnknown { t.Fatal("unknown") }
}
