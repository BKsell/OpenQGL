package main

import "testing"

func mpnHas(fs []MPNFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestMPNGoodManifest(t *testing.T) {
	pol := DefaultMPNPolicy()
	safe, _ := MPNValidateManifestOrigin(
		"https://piston-meta.mojang.com/mc/game/version_manifest_v2.json", pol)
	if !safe {
		t.Fatal("official manifest origin should pass")
	}
}

func TestMPNManifestUnpinned(t *testing.T) {
	pol := DefaultMPNPolicy()
	_, fs := MPNValidateManifestOrigin("https://evil.test/manifest.json", pol)
	if !mpnHas(fs, MPNReasonManifestOriginUnpinned) {
		t.Fatalf("want unpinned origin, got %v", fs)
	}
}

func TestMPNGoodEntries(t *testing.T) {
	pol := DefaultMPNPolicy()
	entries := []MPNEntry{
		{Kind: "client", URL: "https://piston-data.mojang.com/a/client.jar"},
		{Kind: "library", URL: "https://libraries.minecraft.net/com/x.jar"},
	}
	// 官方客户端+libraries 本就跨两个受信主机；MixedHosts 仅在受信集合内告警属噪声，
	// 这里两主机都受信，HostNotPinned 不应出现
	_, fs := MPNValidateEntries(entries, pol)
	for _, f := range fs {
		if f.Reason == MPNReasonHostNotPinned {
			t.Fatalf("pinned hosts must not be flagged: %v", fs)
		}
	}
}

func TestMPNHostNotPinned(t *testing.T) {
	pol := DefaultMPNPolicy()
	entries := []MPNEntry{{Kind: "client", URL: "https://cdn.evil.test/client.jar"}}
	_, fs := MPNValidateEntries(entries, pol)
	if !mpnHas(fs, MPNReasonHostNotPinned) {
		t.Fatalf("want host not pinned, got %v", fs)
	}
}

func TestMPNPlainHTTP(t *testing.T) {
	pol := DefaultMPNPolicy()
	entries := []MPNEntry{{Kind: "asset", URL: "http://resources.download.minecraft.net/a/b"}}
	_, fs := MPNValidateEntries(entries, pol)
	if !mpnHas(fs, MPNReasonPlainHTTP) {
		t.Fatalf("want plain http, got %v", fs)
	}
}

func TestMPNCustomOverrideUntrusted(t *testing.T) {
	pol := DefaultMPNPolicy()
	entries := []MPNEntry{{Kind: "library", URL: "https://modpack-cdn.xyz/x.jar", IsCustom: true}}
	_, fs := MPNValidateEntries(entries, pol)
	if !mpnHas(fs, MPNReasonCustomOverrideUntrusted) {
		t.Fatalf("want custom override untrusted, got %v", fs)
	}
}

func TestMPNCustomAllowed(t *testing.T) {
	pol := DefaultMPNPolicy()
	pol.AllowCustomOverride = true
	entries := []MPNEntry{{Kind: "library", URL: "https://modpack-cdn.xyz/x.jar", IsCustom: true}}
	safe, _ := MPNValidateEntries(entries, pol)
	if !safe {
		t.Fatal("explicitly trusted custom override should pass")
	}
}

func TestMPNUserinfo(t *testing.T) {
	pol := DefaultMPNPolicy()
	_, fs := MPNValidateEntries([]MPNEntry{
		{Kind: "client", URL: "https://user:pass@piston-data.mojang.com/a.jar"},
	}, pol)
	if !mpnHas(fs, MPNReasonUserinfoInURL) {
		t.Fatalf("want userinfo, got %v", fs)
	}
}

func TestMPNHostExtract(t *testing.T) {
	h, s, _ := mpnHostPort("https://Piston-Data.Mojang.com:443/a/b.jar")
	if h != "piston-data.mojang.com:443" || s != "https" {
		t.Fatalf("host extraction wrong %q %q", h, s)
	}
}

func TestMPNFabricPinned(t *testing.T) {
	pol := DefaultMPNPolicy()
	safe, _ := MPNValidateManifestOrigin("https://meta.fabricmc.net/v2/versions", pol)
	if !safe {
		t.Fatal("fabric meta host should be pinned")
	}
}
