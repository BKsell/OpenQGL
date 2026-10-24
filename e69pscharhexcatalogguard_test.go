package main

import "testing"

func TestE69PCHClassifyBlock(t *testing.T) {
	for _, v := range E69PCHBlock { if E69PCHClassify(v) != E69PCHClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69PCHClassifyWarn(t *testing.T) {
	for _, v := range E69PCHWarn { if E69PCHClassify(v) != E69PCHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69PCHClassifyAllow(t *testing.T) {
	for _, v := range E69PCHAllow { if E69PCHClassify(v) != E69PCHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69PCHClassifyUnknown(t *testing.T) {
	if E69PCHClassify("zzz-not-in-any-e69-catalog-88") != E69PCHClassUnknown { t.Fatal("unknown") }
}
