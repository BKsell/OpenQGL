package main

import "testing"

func TestE69HDPClassifyBlock(t *testing.T) {
	for _, v := range E69HDPBlock { if E69HDPClassify(v) != E69HDPClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69HDPClassifyWarn(t *testing.T) {
	for _, v := range E69HDPWarn { if E69HDPClassify(v) != E69HDPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69HDPClassifyAllow(t *testing.T) {
	for _, v := range E69HDPAllow { if E69HDPClassify(v) != E69HDPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69HDPClassifyUnknown(t *testing.T) {
	if E69HDPClassify("zzz-not-in-any-e69-catalog-88") != E69HDPClassUnknown { t.Fatal("unknown") }
}
