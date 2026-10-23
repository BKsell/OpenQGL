package main

// lengthprefixguard.go —— 二进制协议"长度前缀 + 载荷"消息的边界解析守卫。
//
// 背景：
//   启动器与本地服务、调试通道或自定义协议通信时常见 [length][payload] 帧。解析缺陷：
//     - 信任长度字段，按其分配缓冲，遇到超大/0xFFFFFFFF 长度直接 OOM；
//     - 长度字段与实际可用字节不一致（声明 1MB，缓冲只有 10B）造成越界读/截断解析；
//     - 负长度被按无符号处理；
//     - 嵌套消息的内层长度超过外层剩余；
//     - varint 编码过长（non-minimal varint）或永不终止。
//   纯数值一致性判定，不读取真实 socket，不使用正则。前缀 FRM = frame。

const (
	FRMReasonLengthTooLarge     = "frame-declared-length-exceeds-max-frame"
	FRMReasonLengthExceedsData  = "frame-declared-length-exceeds-available-bytes"
	FRMReasonNegativeLength     = "frame-negative-length-coerced"
	FRMReasonNestedOverflow     = "frame-nested-length-exceeds-parent-remainder"
	FRMReasonVarintNonMinimal   = "frame-varint-non-minimal-encoding"
	FRMReasonVarintUnterminated = "frame-varint-unterminated"
	FRMReasonZeroPayload        = "frame-zero-length-payload"
)

// FRMMaxFrame 单帧载荷默认上限（16 MiB）。
const FRMMaxFrame = 16 << 20

// FRMFinding 记录一处帧解析问题。
type FRMFinding struct {
	Reason string
	Detail string
}

// FRMAuditFrame 校验单帧长度声明。
func FRMAuditFrame(declaredLen, available, maxLen int64) (safe bool, findings []FRMFinding) {
	if maxLen <= 0 {
		maxLen = FRMMaxFrame
	}
	if declaredLen < 0 {
		findings = append(findings, FRMFinding{Reason: FRMReasonNegativeLength})
	}
	if declaredLen == 0 {
		findings = append(findings, FRMFinding{Reason: FRMReasonZeroPayload})
	}
	if declaredLen > maxLen {
		findings = append(findings, FRMFinding{Reason: FRMReasonLengthTooLarge,
			Detail: frmItoa(declaredLen)})
	}
	if declaredLen > available {
		findings = append(findings, FRMFinding{Reason: FRMReasonLengthExceedsData,
			Detail: frmItoa(declaredLen) + ">" + frmItoa(available)})
	}
	return len(findings) == 0, findings
}

// FRMAuditNested 校验内层帧长度不超过外层剩余字节。
func FRMAuditNested(innerLen, parentHeaderEnd, parentTotalLen int64) (safe bool, findings []FRMFinding) {
	remainder := parentTotalLen - parentHeaderEnd
	if remainder < 0 {
		return false, []FRMFinding{{Reason: FRMReasonNestedOverflow, Detail: "header>parent"}}
	}
	if innerLen < 0 {
		findings = append(findings, FRMFinding{Reason: FRMReasonNegativeLength})
	}
	if innerLen > remainder {
		findings = append(findings, FRMFinding{Reason: FRMReasonNestedOverflow,
			Detail: frmItoa(innerLen) + ">" + frmItoa(remainder)})
	}
	return len(findings) == 0, findings
}

// FRMDecodeVarint 解析 LEB128 无符号 varint。
// 返回 (value, consumedBytes, ok, minimal)：minimal=false 表示编码非最短形式。
func FRMDecodeVarint(buf []byte) (value uint64, consumed int, ok bool, minimal bool) {
	var result uint64
	shift := uint(0)
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		if i >= 10 {
			return 0, i, false, false // uint64 最多 10 字节
		}
		if i == 9 && b > 1 {
			return 0, i + 1, false, false // 超出 uint64
		}
		result |= uint64(b&0x7f) << shift
		consumed = i + 1
		if b&0x80 == 0 {
			// 最短形式：用了 i+1 字节，则值必须放不下前 i*7 位。
			if i > 0 {
				var minValForLen uint64 = 1
				for k := 0; k < 7*i; k++ {
					minValForLen <<= 1
				}
				if result < minValForLen {
					return result, consumed, true, false
				}
			}
			return result, consumed, true, true
		}
		shift += 7
	}
	return 0, consumed, false, false // 未终止
}

// FRMAuditVarint 直接审计一段 varint 字节。
func FRMAuditVarint(buf []byte) (safe bool, findings []FRMFinding) {
	_, _, ok, minimal := FRMDecodeVarint(buf)
	if !ok {
		return false, []FRMFinding{{Reason: FRMReasonVarintUnterminated}}
	}
	if !minimal {
		findings = append(findings, FRMFinding{Reason: FRMReasonVarintNonMinimal})
	}
	return len(findings) == 0, findings
}

func frmItoa(i int64) string {
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

// FRMHasReason 判定结果含某类问题。
func FRMHasReason(findings []FRMFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
