package main

import (
	"testing"
)

func TestQuickplay_Singleplayer(t *testing.T) {
	if err := ValidateQuickPlayArg("singleplayer", "My World"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuickPlayArg("singleplayer", "../etc"); err == nil {
		t.Fatal("traversal must fail")
	}
	if err := ValidateQuickPlayArg("singleplayer", "a/b"); err == nil {
		t.Fatal("slash must fail")
	}
}

func TestQuickplay_Multiplayer(t *testing.T) {
	if err := ValidateQuickPlayArg("multiplayer", "mc.example.com:25565"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuickPlayArg("multiplayer", "mc.example.com"); err != nil {
		t.Fatalf("bare host should default port: %v", err)
	}
	if err := ValidateQuickPlayArg("multiplayer", "mc.example.com:99999"); err == nil {
		t.Fatal("bad port must fail")
	}
}

func TestQuickplay_RealmsAndGarbage(t *testing.T) {
	if err := ValidateQuickPlayArg("realms", "12345"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuickPlayArg("realms", "12/34"); err == nil {
		t.Fatal("slashes in realms id must fail")
	}
	if err := ValidateQuickPlayArg("nonsense", "x"); err == nil {
		t.Fatal("unknown mode must fail")
	}
	if err := ValidateQuickPlayArg("multiplayer", ""); err == nil {
		t.Fatal("empty must fail")
	}
}

func TestAllowQuickplay(t *testing.T) {
	if !AllowQuickplay("multiplayer", "1.2.3.4:25565") {
		t.Fatal("should allow clean mp")
	}
	if AllowQuickplay("singleplayer", "..\\win") {
		t.Fatal("should block traversal")
	}
}
