package main

import "testing"

// nbtName 编码一个 NBT 名称（2 字节大端长度 + UTF-8）。
func nbtName(s string) []byte {
	b := []byte(s)
	return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)
}

func TestNBTTrivialCompound(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{})
	// 根 COMPOUND，空名，直接 TAG_End
	data := []byte{nbtTagCompound, 0, 0, nbtTagEnd}
	if safe, _ := a.NBTAudit(data); !safe {
		t.Fatal("empty root compound should pass")
	}
}

func TestNBTByteAndInt(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{})
	var data []byte
	data = append(data, nbtTagCompound)
	data = append(data, nbtName("")...)
	data = append(data, nbtTagByte)
	data = append(data, nbtName("b")...)
	data = append(data, 7)
	data = append(data, nbtTagInt)
	data = append(data, nbtName("i")...)
	data = append(data, 0, 0, 1, 0) // 256
	data = append(data, nbtTagEnd)
	if safe, fs := a.NBTAudit(data); !safe {
		t.Fatalf("valid byte+int compound should pass: %v", fs)
	}
}

func TestNBTEmptyDoc(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{})
	if safe, _ := a.NBTAudit(nil); !safe {
		t.Fatal("empty nbt document should be accepted")
	}
}

func TestNBTBadRootType(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{})
	_, fs := a.NBTAudit([]byte{nbtTagString, 0})
	if !NBTHasReason(fs, NBTReasonUnknownTagType) {
		t.Fatalf("non-compound root must flag: %v", fs)
	}
}

func TestNBTHugeIntArray(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{})
	var data []byte
	data = append(data, nbtTagCompound, 0, 0)
	data = append(data, nbtTagIntArray)
	data = append(data, nbtName("big")...)
	data = append(data, 0x7f, 0xff, 0xff, 0xff) // ~21 亿元，超限
	if safe, fs := a.NBTAudit(data); !NBTHasReason(fs, NBTReasonArrayLengthHuge) {
		t.Fatalf("huge int array length must flag (safe=%v): %v", safe, fs)
	}
}

func TestNBTNegativeArray(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{})
	var data []byte
	data = append(data, nbtTagCompound, 0, 0)
	data = append(data, nbtTagByteArray)
	data = append(data, nbtName("neg")...)
	data = append(data, 0xff, 0xff, 0xff, 0xff) // -1
	if safe, fs := a.NBTAudit(data); !NBTHasReason(fs, NBTReasonArrayLengthHuge) {
		t.Fatalf("negative array length must flag (safe=%v): %v", safe, fs)
	}
}

func TestNBTStringBeyondBytes(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{})
	var data []byte
	data = append(data, nbtTagCompound, 0, 0)
	data = append(data, nbtTagString)
	data = append(data, nbtName("s")...)
	data = append(data, 0, 10) // 声称 10 字节，但没有后续
	if safe, fs := a.NBTAudit(data); !NBTHasReason(fs, NBTReasonStringLengthBad) {
		t.Fatalf("string exceeding bytes must flag (safe=%v): %v", safe, fs)
	}
}

func TestNBTTruncatedInt(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{})
	var data []byte
	data = append(data, nbtTagCompound, 0, 0)
	data = append(data, nbtTagInt)
	data = append(data, nbtName("i")...)
	data = append(data, 0, 1) // 只给 2 字节，int 需 4
	if safe, fs := a.NBTAudit(data); !NBTHasReason(fs, NBTReasonTruncatedPayload) {
		t.Fatalf("truncated int payload must flag (safe=%v): %v", safe, fs)
	}
}

func TestNBTBadListType(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{})
	var data []byte
	data = append(data, nbtTagCompound, 0, 0)
	data = append(data, nbtTagList)
	data = append(data, nbtName("l")...)
	data = append(data, 99) // 非法元素类型
	data = append(data, 0, 0, 0, 1)
	if safe, fs := a.NBTAudit(data); !NBTHasReason(fs, NBTReasonListTypeBad) {
		t.Fatalf("invalid list element type must flag (safe=%v): %v", safe, fs)
	}
}

func nbtNestedCompound(depth int) []byte {
	// 每层：一个嵌套 COMPOUND 标签 + 名
	var data []byte
	data = append(data, nbtTagCompound)
	data = append(data, nbtName("")...)
	for i := 0; i < depth; i++ {
		data = append(data, nbtTagCompound)
		data = append(data, nbtName("c")...)
	}
	for i := 0; i < depth+1; i++ {
		data = append(data, nbtTagEnd)
	}
	return data
}

func TestNBTDepthExceeded(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{MaxDepth: 4})
	data := nbtNestedCompound(10)
	if safe, fs := a.NBTAudit(data); !NBTHasReason(fs, NBTReasonDepthExceeded) {
		t.Fatalf("nesting beyond max depth must flag (safe=%v): %v", safe, fs)
	}
}

func TestNBTDepthWithinLimit(t *testing.T) {
	a := NBTNewAuditor(NBTLimits{MaxDepth: 32})
	data := nbtNestedCompound(5)
	if safe, fs := a.NBTAudit(data); !safe {
		t.Fatalf("shallow nesting within limit should pass: %v", fs)
	}
}
