package main

import "testing"

func TestE70QPLClassifyBlock(t *testing.T) {
	for _, v := range E70QPLBlock { if E70QPLClassify(v) != E70QPLClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70QPLClassifyWarn(t *testing.T) {
	for _, v := range E70QPLWarn { if E70QPLClassify(v) != E70QPLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70QPLClassifyAllow(t *testing.T) {
	for _, v := range E70QPLAllow { if E70QPLClassify(v) != E70QPLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70QPLClassifyUnknown(t *testing.T) {
	if E70QPLClassify("zzz-not-in-any-e70-catalog-99") != E70QPLClassUnknown { t.Fatal("unknown") }
}
