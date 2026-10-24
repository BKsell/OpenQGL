package main

import "testing"

func TestE70PNSClassifyBlock(t *testing.T) {
	for _, v := range E70PNSBlock { if E70PNSClassify(v) != E70PNSClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PNSClassifyWarn(t *testing.T) {
	for _, v := range E70PNSWarn { if E70PNSClassify(v) != E70PNSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PNSClassifyAllow(t *testing.T) {
	for _, v := range E70PNSAllow { if E70PNSClassify(v) != E70PNSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PNSClassifyUnknown(t *testing.T) {
	if E70PNSClassify("zzz-not-in-any-e70-catalog-99") != E70PNSClassUnknown { t.Fatal("unknown") }
}
