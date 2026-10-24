package main

import "testing"

func TestE69PDBClassifyBlock(t *testing.T) {
	for _, v := range E69PDBBlock { if E69PDBClassify(v) != E69PDBClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69PDBClassifyWarn(t *testing.T) {
	for _, v := range E69PDBWarn { if E69PDBClassify(v) != E69PDBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69PDBClassifyAllow(t *testing.T) {
	for _, v := range E69PDBAllow { if E69PDBClassify(v) != E69PDBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69PDBClassifyUnknown(t *testing.T) {
	if E69PDBClassify("zzz-not-in-any-e69-catalog-88") != E69PDBClassUnknown { t.Fatal("unknown") }
}
