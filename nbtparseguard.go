package main

// nbtparseguard.go —— Minecraft NBT 二进制结构的解析安全守卫。
//
// 背景：
//   NBT（Named Binary Tag）用于 level.dat、区块、部分网络载荷。恶意/损坏 NBT 可导致：
//     - 嵌套极深（LIST/COMPOUND 递归）撑爆调用栈；
//     - 声明的数组/列表长度巨大，按其分配导致 OOM；
//     - 字符串前缀长度为负或超过剩余字节；
//     - List 元素类型非法（>12）、长度与实际负载不符（截断）；
//     - 未知标签类型 ID。
//   本模块只做"结构走查"（不反序列化业务对象），维护深度/计数/剩余预算；纯字节、大端（Java NBT），
//   不使用正则。

const (
	NBTReasonUnknownTagType   = "nbt-unknown-tag-type-id"
	NBTReasonDepthExceeded    = "nbt-compound-list-nesting-depth-exceeded"
	NBTReasonArrayLengthHuge  = "nbt-declared-array-or-list-length-exceeds-budget"
	NBTReasonStringLengthBad  = "nbt-string-prefix-length-negative-or-beyond-bytes"
	NBTReasonListTypeBad      = "nbt-list-element-tag-type-invalid"
	NBTReasonTruncatedPayload = "nbt-payload-truncated-vs-declared-structure"
)

const (
	nbtTagEnd       = 0
	nbtTagByte      = 1
	nbtTagShort     = 2
	nbtTagInt       = 3
	nbtTagLong      = 4
	nbtTagFloat     = 5
	nbtTagDouble    = 6
	nbtTagByteArray = 7
	nbtTagString    = 8
	nbtTagList      = 9
	nbtTagCompound  = 10
	nbtTagIntArray  = 11
	nbtTagLongArray = 12
)

const (
	NBTMaxDepth    = 64
	NBTMaxArrayLen = 200_000_000
)

// NBTFinding 记录一处结构问题。
type NBTFinding struct {
	Reason string
	Offset int
	Detail string
}

// NBTLimits 允许覆盖预算。
type NBTLimits struct {
	MaxDepth    int
	MaxArrayLen int32
}

// NBTAuditor 走查 NBT 字节。
type NBTAuditor struct {
	Limits NBTLimits
}

// NBTNewAuditor 创建审计器。
func NBTNewAuditor(l NBTLimits) *NBTAuditor {
	if l.MaxDepth <= 0 {
		l.MaxDepth = NBTMaxDepth
	}
	if l.MaxArrayLen <= 0 {
		l.MaxArrayLen = NBTMaxArrayLen
	}
	return &NBTAuditor{Limits: l}
}

// NBTAudit 走查一段以"具名根 COMPOUND"开头的 Java NBT；空字节视为合法空文档。
func (a *NBTAuditor) NBTAudit(data []byte) (safe bool, findings []NBTFinding) {
	if len(data) == 0 {
		return true, nil
	}
	pos := 0
	if data[pos] != nbtTagCompound {
		return false, []NBTFinding{{Reason: NBTReasonUnknownTagType, Offset: pos,
			Detail: nbtItoa(int64(data[pos]))}}
	}
	pos++
	var ok bool
	if pos, ok, findings = a.nbtReadName(data, pos, findings); !ok {
		return false, findings
	}
	pos, findings = a.nbtWalkCompound(data, pos, 1, findings)
	return len(findings) == 0, findings
}

// nbtWalkCompound 从 COMPOUND 体内第一个标签开始，直到 TAG_End。
func (a *NBTAuditor) nbtWalkCompound(data []byte, pos, depth int, findings []NBTFinding) (int, []NBTFinding) {
	for {
		if pos >= len(data) {
			return pos, append(findings, NBTFinding{Reason: NBTReasonTruncatedPayload, Offset: pos})
		}
		tagType := int(data[pos])
		pos++
		if tagType == nbtTagEnd {
			return pos, findings
		}
		if tagType < nbtTagByte || tagType > nbtTagLongArray {
			return pos, append(findings, NBTFinding{Reason: NBTReasonUnknownTagType, Offset: pos - 1,
				Detail: nbtItoa(int64(tagType))})
		}
		var ok bool
		if pos, ok, findings = a.nbtReadName(data, pos, findings); !ok {
			return pos, findings
		}
		if (tagType == nbtTagCompound || tagType == nbtTagList) && depth+1 > a.Limits.MaxDepth {
			return pos, append(findings, NBTFinding{Reason: NBTReasonDepthExceeded, Offset: pos})
		}
		var fs []NBTFinding
		pos, fs = a.nbtWalkPayload(data, pos, tagType, depth+1, nil)
		findings = append(findings, fs...)
		if pos > len(data) {
			return pos, append(findings, NBTFinding{Reason: NBTReasonTruncatedPayload, Offset: pos})
		}
	}
}

// nbtWalkPayload 走查单个已知类型标签的负载。
func (a *NBTAuditor) nbtWalkPayload(data []byte, pos, tagType, depth int, findings []NBTFinding) (int, []NBTFinding) {
	switch tagType {
	case nbtTagByte:
		return pos + 1, findings
	case nbtTagShort:
		return pos + 2, findings
	case nbtTagInt, nbtTagFloat:
		return pos + 4, findings
	case nbtTagLong, nbtTagDouble:
		return pos + 8, findings
	case nbtTagByteArray, nbtTagIntArray, nbtTagLongArray:
		return a.nbtWalkArray(data, pos, tagType, findings)
	case nbtTagString:
		npos, _, fs2 := a.nbtReadName(data, pos, findings)
		return npos, fs2
	case nbtTagList:
		return a.nbtWalkList(data, pos, depth, findings)
	case nbtTagCompound:
		return a.nbtWalkCompound(data, pos, depth, findings)
	default:
		return pos, append(findings, NBTFinding{Reason: NBTReasonUnknownTagType, Offset: pos,
			Detail: nbtItoa(int64(tagType))})
	}
}

func (a *NBTAuditor) nbtWalkArray(data []byte, pos, tagType int, findings []NBTFinding) (int, []NBTFinding) {
	n, np, ok := a.nbtReadInt32(data, pos)
	if !ok {
		return np, append(findings, NBTFinding{Reason: NBTReasonTruncatedPayload, Offset: pos})
	}
	pos = np
	if n < 0 || n > a.Limits.MaxArrayLen {
		return pos, append(findings, NBTFinding{Reason: NBTReasonArrayLengthHuge, Offset: pos,
			Detail: nbtItoa(int64(n))})
	}
	elem := 1
	if tagType == nbtTagIntArray {
		elem = 4
	} else if tagType == nbtTagLongArray {
		elem = 8
	}
	total := int64(n) * int64(elem)
	if total > int64(len(data)-pos) {
		return pos, append(findings, NBTFinding{Reason: NBTReasonTruncatedPayload, Offset: pos,
			Detail: nbtItoa(total)})
	}
	return pos + int(total), findings
}

func (a *NBTAuditor) nbtWalkList(data []byte, pos, depth int, findings []NBTFinding) (int, []NBTFinding) {
	if pos >= len(data) {
		return pos, append(findings, NBTFinding{Reason: NBTReasonTruncatedPayload, Offset: pos})
	}
	elemType := int(data[pos])
	pos++
	if elemType < nbtTagByte || elemType > nbtTagLongArray {
		// 允许空列表（length==0）携带 TAG_End 类型
		n, np, ok := a.nbtReadInt32(data, pos)
		if ok && n == 0 && elemType == nbtTagEnd {
			return np, findings
		}
		return pos, append(findings, NBTFinding{Reason: NBTReasonListTypeBad, Offset: pos - 1,
			Detail: nbtItoa(int64(elemType))})
	}
	n, np, ok := a.nbtReadInt32(data, pos)
	if !ok {
		return np, append(findings, NBTFinding{Reason: NBTReasonTruncatedPayload, Offset: pos})
	}
	pos = np
	if n < 0 || n > a.Limits.MaxArrayLen {
		return pos, append(findings, NBTFinding{Reason: NBTReasonArrayLengthHuge, Offset: pos,
			Detail: nbtItoa(int64(n))})
	}
	if depth+1 > a.Limits.MaxDepth {
		return pos, append(findings, NBTFinding{Reason: NBTReasonDepthExceeded, Offset: pos})
	}
	for i := int32(0); i < n; i++ {
		var fs []NBTFinding
		pos, fs = a.nbtWalkPayload(data, pos, elemType, depth+1, nil)
		findings = append(findings, fs...)
		if pos > len(data) {
			return pos, append(findings, NBTFinding{Reason: NBTReasonTruncatedPayload, Offset: pos})
		}
	}
	return pos, findings
}

// nbtReadName 读取 2 字节大端长度前缀的名称。
func (a *NBTAuditor) nbtReadName(data []byte, pos int, findings []NBTFinding) (npos int, ok bool, fs []NBTFinding) {
	n, np, ok := a.nbtReadInt16(data, pos)
	if !ok {
		return pos, false, append(findings, NBTFinding{Reason: NBTReasonTruncatedPayload, Offset: pos})
	}
	if n < 0 || int64(np)+int64(n) > int64(len(data)) {
		return np, false, append(findings, NBTFinding{Reason: NBTReasonStringLengthBad, Offset: pos,
			Detail: nbtItoa(int64(n))})
	}
	return np + n, true, findings
}

func (a *NBTAuditor) nbtReadInt16(data []byte, pos int) (n int, npos int, ok bool) {
	if pos+2 > len(data) {
		return 0, pos, false
	}
	v := int16(uint16(data[pos])<<8 | uint16(data[pos+1]))
	return int(v), pos + 2, true
}

func (a *NBTAuditor) nbtReadInt32(data []byte, pos int) (n int32, npos int, ok bool) {
	if pos+4 > len(data) {
		return 0, pos, false
	}
	v := int32(uint32(data[pos])<<24 | uint32(data[pos+1])<<16 |
		uint32(data[pos+2])<<8 | uint32(data[pos+3]))
	return v, pos + 4, true
}

func nbtItoa(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// NBTHasReason 判定结果含某类问题。
func NBTHasReason(findings []NBTFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
