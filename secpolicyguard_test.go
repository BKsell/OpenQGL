package main

import "testing"

func scpHas(fs []SCPFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestSCPCleanProps(t *testing.T) {
	pol := DefaultSCPPolicy()
	safe, _ := SCPInspectProps(SCPPropsView{SecurityManagerSet: true}, pol)
	if !safe {
		t.Fatal("no policy overrides should be safe")
	}
}

func TestSCPAbsolutePolicy(t *testing.T) {
	pol := DefaultSCPPolicy()
	safe, _ := SCPInspectProps(SCPPropsView{PolicyLocation: `file:///C:/mc/app.policy`}, pol)
	if !safe {
		t.Fatal("absolute file policy should pass")
	}
}

func TestSCPRemotePolicy(t *testing.T) {
	pol := DefaultSCPPolicy()
	_, fs := SCPInspectProps(SCPPropsView{PolicyLocation: "https://evil/app.policy"}, pol)
	if !scpHas(fs, SCPReasonRemotePolicy) {
		t.Fatalf("want remote policy, got %v", fs)
	}
}

func TestSCPRelativePolicy(t *testing.T) {
	pol := DefaultSCPPolicy()
	_, fs := SCPInspectProps(SCPPropsView{PolicyLocation: "app.policy", PolicyWritable: true}, pol)
	if !scpHas(fs, SCPReasonRelativePolicy) {
		t.Fatalf("want relative policy, got %v", fs)
	}
	if !scpHas(fs, SCPReasonWritablePolicy) {
		t.Fatalf("want writable policy, got %v", fs)
	}
}

func TestSCPPropertiesOverride(t *testing.T) {
	pol := DefaultSCPPolicy()
	_, fs := SCPInspectProps(SCPPropsView{
		PropertiesLocation: `file:///C:/mc/override.properties`,
		PropertiesOverride: true,
	}, pol)
	if !scpHas(fs, SCPReasonPolicyOverrides) {
		t.Fatalf("want full override, got %v", fs)
	}
}

func TestSCPPolicyURLReplaced(t *testing.T) {
	pol := DefaultSCPPolicy()
	_, fs := SCPInspectProps(SCPPropsView{PolicyURLReplaced: true}, pol)
	if !scpHas(fs, SCPReasonPolicyURLReplaced) {
		t.Fatalf("want policy.url replaced, got %v", fs)
	}
}

func TestSCPAllPermission(t *testing.T) {
	pol := DefaultSCPPolicy()
	text := `grant { permission java.security.AllPermission; };`
	_, fs := SCPInspectPolicyText(text, pol)
	if !scpHas(fs, SCPReasonAllPermission) {
		t.Fatalf("want allpermission, got %v", fs)
	}
}

func TestSCPDangerousRuntime(t *testing.T) {
	pol := DefaultSCPPolicy()
	text := `grant codeBase "file:/app/-" {
		permission java.lang.RuntimePermission "createClassLoader";
	};`
	_, fs := SCPInspectPolicyText(text, pol)
	if !scpHas(fs, SCPReasonDangerousPermission) {
		t.Fatalf("want dangerous runtime, got %v", fs)
	}
}

func TestSCPSuppressAccess(t *testing.T) {
	pol := DefaultSCPPolicy()
	text := `grant codeBase "file:/app/-" {
		permission java.lang.reflect.ReflectPermission "suppressAccessChecks";
	};`
	_, fs := SCPInspectPolicyText(text, pol)
	if !scpHas(fs, SCPReasonDangerousPermission) {
		t.Fatalf("want reflect permission, got %v", fs)
	}
}

func TestSCPGlobalGrant(t *testing.T) {
	pol := DefaultSCPPolicy()
	text := `grant {
		permission java.util.PropertyPermission "*", "read";
	};`
	_, fs := SCPInspectPolicyText(text, pol)
	if !scpHas(fs, SCPReasonDangerousPermission) {
		t.Fatalf("want global grant danger, got %v", fs)
	}
}

func TestSCPScopedGrantOK(t *testing.T) {
	pol := DefaultSCPPolicy()
	// 限定 codeBase 且只给读属性这类非高危权限
	text := `grant codeBase "file:/app/-" {
		permission java.util.PropertyPermission "user.dir", "read";
	};`
	safe, _ := SCPInspectPolicyText(text, pol)
	if !safe {
		t.Fatal("scoped low-risk grant should pass")
	}
}

func TestSCPAllowAllPolicy(t *testing.T) {
	pol := DefaultSCPPolicy()
	pol.AllowAllPermission = true
	pol.AllowDangerousRuntime = true
	text := `grant { permission java.security.AllPermission; };`
	safe, _ := SCPInspectPolicyText(text, pol)
	if !safe {
		t.Fatal("permissive policy should pass when allowed")
	}
}
