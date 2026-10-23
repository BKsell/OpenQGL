package main

import "testing"

func tstHas(fs []TSTFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestTSTDefaultStore(t *testing.T) {
	pol := DefaultTSTPolicy()
	// 不设置任何 trustStore 属性：使用 JDK 默认信任根，安全
	safe, _ := TSTInspectSystemProps(map[string]string{}, pol)
	if !safe {
		t.Fatal("default jdk trust should be safe")
	}
}

func TestTSTAbsolutePKCS12(t *testing.T) {
	pol := DefaultTSTPolicy()
	safe, _ := TSTInspectStore(TSTStoreView{
		StorePath:  `C:\Users\me\.openqgl\custom-ca.p12`,
		StoreType:  "PKCS12",
		PathExists: true,
	}, pol)
	if !safe {
		t.Fatal("absolute pkcs12 read-only store should pass")
	}
}

func TestTSTRelativePath(t *testing.T) {
	pol := DefaultTSTPolicy()
	_, fs := TSTInspectStore(TSTStoreView{StorePath: "certs\\ca.jks", StoreType: "JKS"}, pol)
	if !tstHas(fs, TSTReasonTrustStorePath) {
		t.Fatalf("want relative path, got %v", fs)
	}
}

func TestTSTWritableStore(t *testing.T) {
	pol := DefaultTSTPolicy()
	_, fs := TSTInspectStore(TSTStoreView{
		StorePath:    `C:\mc\trust.jks`,
		StoreType:    "JKS",
		PathExists:   true,
		PathWritable: true,
	}, pol)
	if !tstHas(fs, TSTReasonTrustStorePath) {
		t.Fatalf("want writable store, got %v", fs)
	}
}

func TestTSTPasswordOnArg(t *testing.T) {
	pol := DefaultTSTPolicy()
	_, fs := TSTInspectSystemProps(map[string]string{
		"javax.net.ssl.trustStorePassword": "changeit",
	}, pol)
	if !tstHas(fs, TSTReasonTrustStorePasswordArg) {
		t.Fatalf("want password on arg, got %v", fs)
	}
}

func TestTSTStoreTypeNone(t *testing.T) {
	pol := DefaultTSTPolicy()
	_, fs := TSTInspectSystemProps(map[string]string{
		"javax.net.ssl.trustStore":     `C:\ca.jks`,
		"javax.net.ssl.trustStoreType": "NONE",
	}, pol)
	if !tstHas(fs, TSTReasonTrustStoreTypeWeak) {
		t.Fatalf("want NONE type, got %v", fs)
	}
}

func TestTSTStoreTypeUnknown(t *testing.T) {
	pol := DefaultTSTPolicy()
	_, fs := TSTInspectStore(TSTStoreView{StorePath: `C:\ca`, StoreType: "WINDOWS-ROOT"}, pol)
	if !tstHas(fs, TSTReasonTrustStoreTypeWeak) {
		t.Fatalf("want unknown type, got %v", fs)
	}
}

func TestTSTTrustAllProp(t *testing.T) {
	pol := DefaultTSTPolicy()
	_, fs := TSTInspectSystemProps(map[string]string{"app.trustAllCerts": "true"}, pol)
	if !tstHas(fs, TSTReasonTrustAllProp) {
		t.Fatalf("want trust-all prop, got %v", fs)
	}
}

func TestTSTManagerEmptyIssuers(t *testing.T) {
	_, fs := TSTInspectManager(TSTManagerView{GetAcceptedIssuersEmpty: true})
	if !tstHas(fs, TSTReasonEmptyAcceptedIssuers) {
		t.Fatalf("want empty issuers, got %v", fs)
	}
	if !tstHas(fs, TSTReasonPermissiveManager) {
		t.Fatalf("want permissive manager, got %v", fs)
	}
}

func TestTSTManagerCheckNoopInstalled(t *testing.T) {
	_, fs := TSTInspectManager(TSTManagerView{
		CheckServerTrustedNoop:  true,
		InstalledIntoSSLContext: true,
	})
	if !tstHas(fs, TSTReasonCheckTrustedNoop) {
		t.Fatalf("want check noop, got %v", fs)
	}
	if !tstHas(fs, TSTReasonPermissiveSSLContext) {
		t.Fatalf("want permissive ssl context, got %v", fs)
	}
}

func TestTSTManagerStrict(t *testing.T) {
	safe, _ := TSTInspectManager(TSTManagerView{
		GetAcceptedIssuersEmpty: false,
	})
	if !safe {
		t.Fatal("strict manager should pass")
	}
}

func TestTSTIsAbsPath(t *testing.T) {
	if !tstIsAbsPath(`D:\mc\c.jks`) || !tstIsAbsPath("/home/mc/c.jks") {
		t.Fatal("absolute paths not recognized")
	}
	if tstIsAbsPath("rel\\c.jks") {
		t.Fatal("relative path misdetected")
	}
}
