package main

import (
	"testing"
)

func TestSourceFromHost(t *testing.T) {
	if sourceFromHost("libraries.minecraft.net") != ChecksumMojang {
		t.Fatal("mojang host should classify mojang")
	}
	if sourceFromHost("api.modrinth.com") != ChecksumModrinth {
		t.Fatal("modrinth host")
	}
	if sourceFromHost("127.0.0.1") != ChecksumLocalUMFS {
		t.Fatal("local host")
	}
}

func TestChooseAlgo(t *testing.T) {
	if chooseChecksumAlgo(ChecksumMojang) != AlgoSHA1 {
		t.Fatal("mojang must stay sha1")
	}
	if chooseChecksumAlgo(ChecksumAuthlib) != AlgoSHA256 {
		t.Fatal("authlib must stay sha256")
	}
	if chooseChecksumAlgo(ChecksumModrinth) != AlgoSHA512 {
		t.Fatal("modrinth prefer sha512")
	}
	if chooseChecksumAlgo(ChecksumLocalUMFS) != AlgoLocal {
		t.Fatal("local uses umfs")
	}
	if chooseChecksumAlgo(ChecksumUnknown) != "" {
		t.Fatal("unknown must not pick an algo")
	}
}

func TestIsExternalAlgorithm(t *testing.T) {
	if !isExternalAlgorithm(AlgoSHA1) || !isExternalAlgorithm(AlgoSHA256) || !isExternalAlgorithm(AlgoSHA512) {
		t.Fatal("external algos must be marked external")
	}
	if isExternalAlgorithm(AlgoLocal) {
		t.Fatal("umfs is not external")
	}
}
