package main

import "testing"

func dzHas(fs []DZFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestDZCleanBytes(t *testing.T) {
	pol := DefaultDZPolicy()
	safe, _ := DZInspectBytes([]byte(`{"name":"fabric-loader-0.15","version":"1.20.1"}`), pol)
	if !safe {
		t.Fatal("plain json should be safe as bytes")
	}
}

func TestDZJavaStreamMagic(t *testing.T) {
	pol := DefaultDZPolicy()
	_, fs := DZInspectBytes([]byte{0xAC, 0xED, 0x00, 0x05, 'h', 'i'}, pol)
	if !dzHas(fs, DZReasonJavaStreamMagic) {
		t.Fatalf("want java stream magic, got %v", fs)
	}
}

func TestDZGadgetClassBytes(t *testing.T) {
	pol := DefaultDZPolicy()
	payload := append([]byte{0xAC, 0xED, 0x00, 0x05},
		[]byte("org.apache.commons.collections.functors.InvokerTransformer")...)
	_, fs := DZInspectBytes(payload, pol)
	if !dzHas(fs, DZReasonGadgetClass) {
		t.Fatalf("want gadget class, got %v", fs)
	}
}

func TestDZTemplatesImpl(t *testing.T) {
	pol := DefaultDZPolicy()
	_, fs := DZInspectBytes([]byte("prefix com.sun...TemplatesImpl suffix"), pol)
	if !dzHas(fs, DZReasonTemplatesImpl) {
		t.Fatalf("want templatesimpl, got %v", fs)
	}
}

func TestDZJavaStreamAllowedWithFilter(t *testing.T) {
	pol := DefaultDZPolicy()
	pol.AllowJavaStreamWithAllowlist = true
	// 无 gadget 类名的普通流（仅魔数），配合白名单策略不被魔数判拒
	safe, fs := DZInspectBytes([]byte{0xAC, 0xED, 0x00, 0x05, 'a', 'b'}, pol)
	if !safe || dzHas(fs, DZReasonJavaStreamMagic) {
		t.Fatalf("allowlisted stream magic should not flag, got %v", fs)
	}
}

func TestDZYamlTag(t *testing.T) {
	pol := DefaultDZPolicy()
	yaml := "db: !!javax.script.ScriptEngineManager\n  url: x"
	_, fs := DZInspectYAML(yaml, pol)
	if !dzHas(fs, DZReasonYamlTypeTag) {
		t.Fatalf("want yaml tag, got %v", fs)
	}
}

func TestDZYamlBracketTag(t *testing.T) {
	pol := DefaultDZPolicy()
	yaml := "x: !<java.lang.ProcessBuilder> []"
	_, fs := DZInspectYAML(yaml, pol)
	if !dzHas(fs, DZReasonYamlTypeTag) {
		t.Fatalf("want bracket tag, got %v", fs)
	}
}

func TestDZYamlClean(t *testing.T) {
	pol := DefaultDZPolicy()
	safe, _ := DZInspectYAML("name: hello\nversion: 1\nlist:\n  - a\n  - b\n", pol)
	if !safe {
		t.Fatal("plain yaml should be safe")
	}
}

func TestDZFastjsonType(t *testing.T) {
	pol := DefaultDZPolicy()
	js := `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x/a"}`
	_, fs := DZInspectJSONObject(js, pol)
	if !dzHas(fs, DZReasonPolymorphicType) {
		t.Fatalf("want @type, got %v", fs)
	}
	if !dzHas(fs, DZReasonJNDIInType) {
		t.Fatalf("want jndi ref, got %v", fs)
	}
}

func TestDZJacksonType(t *testing.T) {
	pol := DefaultDZPolicy()
	_, fs := DZInspectJSONObject(`{"$type":"System.IO.StreamWriter"}`, pol)
	if !dzHas(fs, DZReasonPolymorphicType) {
		t.Fatalf("want $type, got %v", fs)
	}
}

func TestDZFilterMissing(t *testing.T) {
	_, fs := DZRequireObjectInputFilter(nil)
	if !dzHas(fs, DZReasonObjectInputFilterMissing) {
		t.Fatalf("want missing filter, got %v", fs)
	}
}

func TestDZFilterWildcard(t *testing.T) {
	_, fs := DZRequireObjectInputFilter([]string{"com.example.*"})
	if !dzHas(fs, DZReasonObjectInputFilterMissing) {
		t.Fatalf("want wildcard reject, got %v", fs)
	}
}

func TestDZFilterConcreteOK(t *testing.T) {
	safe, _ := DZRequireObjectInputFilter([]string{"com.example.ProfileData", "java.util.HashMap"})
	if !safe {
		t.Fatal("concrete class allowlist should pass")
	}
}
