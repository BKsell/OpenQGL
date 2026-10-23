package main

import "testing"

func TestPSCBlock(t *testing.T){
	for _, n := range PSCBlock { if r := PSCAudit(n); !PSCHas(r,PSCReasonBlock) { t.Fatalf("port/code %d block",n) } }
}

func TestPSCWarn(t *testing.T){
	for _, n := range PSCWarn { if r := PSCAudit(n); !PSCHas(r,PSCReasonWarn) { t.Fatalf("%d warn",n) } }
}

func TestPSCSafe(t *testing.T){
	for _, n := range PSCSafe { if r := PSCAudit(n); !r.Safe { t.Fatalf("%d safe",n) } }
}

func TestPSCRange(t *testing.T){
	if r := PSCAudit(1-1); !PSCHas(r,PSCReasonRange){ t.Fatal("below range") }
	if r := PSCAudit(65535+1); !PSCHas(r,PSCReasonRange){ t.Fatal("above range") }
}
