package main

import "testing"

func TestE69PBTClassifyBlock(t *testing.T) {
	for _, v := range E69PBTBlock { if E69PBTClassify(v) != E69PBTClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69PBTClassifyWarn(t *testing.T) {
	for _, v := range E69PBTWarn { if E69PBTClassify(v) != E69PBTClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69PBTClassifyAllow(t *testing.T) {
	for _, v := range E69PBTAllow { if E69PBTClassify(v) != E69PBTClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69PBTClassifyUnknown(t *testing.T) {
	if E69PBTClassify("zzz-not-in-any-e69-catalog-88") != E69PBTClassUnknown { t.Fatal("unknown") }
}
