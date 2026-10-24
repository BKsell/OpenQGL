package main

import "testing"

func TestE70SNCClassifyBlock(t *testing.T) {
	for _, v := range E70SNCBlock { if E70SNCClassify(v) != E70SNCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70SNCClassifyWarn(t *testing.T) {
	for _, v := range E70SNCWarn { if E70SNCClassify(v) != E70SNCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70SNCClassifyAllow(t *testing.T) {
	for _, v := range E70SNCAllow { if E70SNCClassify(v) != E70SNCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70SNCClassifyUnknown(t *testing.T) {
	if E70SNCClassify("zzz-not-in-any-e70-catalog-99") != E70SNCClassUnknown { t.Fatal("unknown") }
}
