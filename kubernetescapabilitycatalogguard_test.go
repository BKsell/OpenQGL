package main

import "testing"

func TestK8SClassifyBlock(t *testing.T) {
	for _, v := range K8SBlock { if K8SClassify(v) != K8SClassBlock { t.Fatalf("%s block", v) } }
}

func TestK8SClassifyWarn(t *testing.T) {
	for _, v := range K8SWarn { if K8SClassify(v) != K8SClassWarn { t.Fatalf("%s warn", v) } }
}

func TestK8SClassifyAllow(t *testing.T) {
	for _, v := range K8SAllow { if K8SClassify(v) != K8SClassAllow { t.Fatalf("%s allow", v) } }
}

func TestK8SClassifyUnknown(t *testing.T) {
	if K8SClassify("zzz-not-in-any-catalog-9") != K8SClassUnknown { t.Fatal("unknown") }
}

func TestK8SCaseInsensitive(t *testing.T) {
	if len(K8SBlock) > 0 { v := K8SBlock[0]; if K8SClassify(v) == K8SClassify("") {} }
}
