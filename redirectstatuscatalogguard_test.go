package main

import "testing"

func TestRSCBlock(t *testing.T){
	for _, n := range RSCBlock { if r := RSCAudit(n); !RSCHas(r,RSCReasonBlock) { t.Fatalf("port/code %d block",n) } }
}

func TestRSCWarn(t *testing.T){
	for _, n := range RSCWarn { if r := RSCAudit(n); !RSCHas(r,RSCReasonWarn) { t.Fatalf("%d warn",n) } }
}

func TestRSCSafe(t *testing.T){
	for _, n := range RSCSafe { if r := RSCAudit(n); !r.Safe { t.Fatalf("%d safe",n) } }
}

func TestRSCRange(t *testing.T){
	if r := RSCAudit(100-1); !RSCHas(r,RSCReasonRange){ t.Fatal("below range") }
	if r := RSCAudit(599+1); !RSCHas(r,RSCReasonRange){ t.Fatal("above range") }
}
