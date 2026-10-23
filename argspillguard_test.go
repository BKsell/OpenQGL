package main

import "testing"

func apsHas(fs []APSFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestAPSClean(t *testing.T) {
	pol := DefaultAPSPolicy()
	safe, fs := APSInspect([]string{"java", "-Xmx2G", "-cp", "a.jar", "Main", "--user", "bob"}, pol)
	if !safe || len(fs) != 0 {
		t.Fatalf("ordinary args should be safe, got %v", fs)
	}
}

func TestAPSPasswordEq(t *testing.T) {
	pol := DefaultAPSPolicy()
	_, fs := APSInspect([]string{"tool", "--password=hunter2hunter2"}, pol)
	if !apsHas(fs, APSReasonPassword) {
		t.Fatalf("want password, got %v", fs)
	}
}

func TestAPSPasswordNext(t *testing.T) {
	pol := DefaultAPSPolicy()
	_, fs := APSInspect([]string{"tool", "-p", "s3cr3t-value"}, pol)
	if !apsHas(fs, APSReasonPassword) {
		t.Fatalf("want password flag, got %v", fs)
	}
}

func TestAPSAccessToken(t *testing.T) {
	pol := DefaultAPSPolicy()
	_, fs := APSInspect([]string{"java", "-Daccess_token=eyJAAA.BBB.CCC", "Main"}, pol)
	if !apsHas(fs, APSReasonAccessToken) {
		t.Fatalf("want access token, got %v", fs)
	}
}

func TestAPSClientSecret(t *testing.T) {
	pol := DefaultAPSPolicy()
	_, fs := APSInspect([]string{"curl", "--client-secret", "xyz"}, pol)
	if !apsHas(fs, APSReasonClientSecret) {
		t.Fatalf("want client secret, got %v", fs)
	}
}

func TestAPSAPIKey(t *testing.T) {
	pol := DefaultAPSPolicy()
	_, fs := APSInspect([]string{"dl", "api_key=AKIA1234567890"}, pol)
	if !apsHas(fs, APSReasonAPIKey) {
		t.Fatalf("want api key, got %v", fs)
	}
}

func TestAPSRefreshToken(t *testing.T) {
	pol := DefaultAPSPolicy()
	_, fs := APSInspect([]string{"tool", "refresh_token=abcdef0123456789"}, pol)
	if !apsHas(fs, APSReasonRefreshToken) {
		t.Fatalf("want refresh token, got %v", fs)
	}
}

func TestAPSURLCredentials(t *testing.T) {
	pol := DefaultAPSPolicy()
	_, fs := APSInspect([]string{"sync", "https://user:p4ss@db.internal:5432/app"}, pol)
	if !apsHas(fs, APSReasonConnectionURL) {
		t.Fatalf("want credentials in url, got %v", fs)
	}
}

func TestAPSPrivateKey(t *testing.T) {
	pol := DefaultAPSPolicy()
	_, fs := APSInspect([]string{"tool", "-----BEGIN RSA PRIVATE KEY-----"}, pol)
	if !apsHas(fs, APSReasonPrivateKey) {
		t.Fatalf("want private key, got %v", fs)
	}
}

func TestAPSBearer(t *testing.T) {
	pol := DefaultAPSPolicy()
	_, fs := APSInspect([]string{"curl", "Authorization: Bearer abc123secret"}, pol)
	if !apsHas(fs, APSReasonBearerInline) {
		t.Fatalf("want bearer, got %v", fs)
	}
}

func TestAPSSessionWarnOnly(t *testing.T) {
	pol := DefaultAPSPolicy()
	safe, fs := APSInspect([]string{"java", "session_id=abc123def456", "Main"}, pol)
	if !apsHas(fs, APSReasonSessionID) {
		t.Fatalf("want session finding recorded, got %v", fs)
	}
	if !safe {
		t.Fatal("session id should be warn-only by default (still safe)")
	}
}

func TestAPSSessionBlocking(t *testing.T) {
	pol := DefaultAPSPolicy()
	pol.WarnSessionID = true
	safe, _ := APSInspect([]string{"java", "sid=abc123def456", "Main"}, pol)
	if safe {
		t.Fatal("session id should block under strict policy")
	}
}

func TestAPSURLNoCredentials(t *testing.T) {
	if apsURLCredentials("https://api.minecraftservices.com/minecraft/profile") {
		t.Fatal("plain url should not be flagged as credentials")
	}
}
