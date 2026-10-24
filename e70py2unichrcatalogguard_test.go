package main

import "testing"

func TestE70PUCClassifyBlock(t *testing.T) {
	for _, v := range E70PUCBlock { if E70PUCClassify(v) != E70PUCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PUCClassifyWarn(t *testing.T) {
	for _, v := range E70PUCWarn { if E70PUCClassify(v) != E70PUCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PUCClassifyAllow(t *testing.T) {
	for _, v := range E70PUCAllow { if E70PUCClassify(v) != E70PUCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PUCClassifyUnknown(t *testing.T) {
	if E70PUCClassify("zzz-not-in-any-e70-catalog-99") != E70PUCClassUnknown { t.Fatal("unknown") }
}
