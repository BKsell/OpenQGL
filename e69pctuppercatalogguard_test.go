package main

import "testing"

func TestE69PUBClassifyBlock(t *testing.T) {
	for _, v := range E69PUBBlock { if E69PUBClassify(v) != E69PUBClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69PUBClassifyWarn(t *testing.T) {
	for _, v := range E69PUBWarn { if E69PUBClassify(v) != E69PUBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69PUBClassifyAllow(t *testing.T) {
	for _, v := range E69PUBAllow { if E69PUBClassify(v) != E69PUBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69PUBClassifyUnknown(t *testing.T) {
	if E69PUBClassify("zzz-not-in-any-e69-catalog-88") != E69PUBClassUnknown { t.Fatal("unknown") }
}
