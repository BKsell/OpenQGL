package main

// intoverflowguard.go —— 外部长度字段驱动的整数溢出/超大分配守卫。
//
// 背景：
//   解析网络/压缩/二进制数据时，代码常用 count*elementSize、width*height*bpp、
//   uncompressedSize 等"由对端给的长度"分配缓冲或推进偏移。32/64 位乘法溢出后回绕成一个很小
//   的值，会导致：分配过小随后堆/切片越界写；偏移加长度回绕绕过边界检查；负值/0 长度引发异常
//   逻辑。zip/tar/png/自定义协议、Modrinth 分片等都要防。
//   本模块提供一组纯整数校验：乘法溢出、加法溢出、对齐回绕、范围/上限闸门。只依赖 math/bits
//   的稳定语义封装，不使用正则。

import "math/bits"

const (
	IOVReasonMulOverflow   = "int-multiplication-overflow"
	IOVReasonAddOverflow   = "int-offset-addition-overflow"
	IOVReasonNegativeSize  = "int-negative-size"
	IOVReasonZeroSize      = "int-zero-size"
	IOVReasonExceedsLimit  = "int-size-exceeds-policy-limit"
	IOVReasonAlignOverflow = "int-alignment-rounding-overflow"
)

// IOVFinding 记录一处整数风险。
type IOVFinding struct {
	Reason string
	Detail string
}

// IOVPolicy 设定尺寸上限（字节）。
type IOVPolicy struct {
	MaxAllocation int64
	RejectZero    bool
}

// DefaultIOVPolicy 给出 512MiB 的单缓冲上限。
func DefaultIOVPolicy() IOVPolicy {
	return IOVPolicy{MaxAllocation: 512 * 1024 * 1024, RejectZero: false}
}

// IOVCheckedMul 计算 a*b，带溢出与上限判定。
func IOVCheckedMul(a, b int64, policy IOVPolicy) (result int64, safe bool, findings []IOVFinding) {
	if a < 0 || b < 0 {
		findings = append(findings, IOVFinding{Reason: IOVReasonNegativeSize})
		return 0, false, findings
	}
	hi, lo := bits.Mul64(uint64(a), uint64(b))
	if hi != 0 || lo > uint64(1<<63-1) {
		findings = append(findings, IOVFinding{Reason: IOVReasonMulOverflow})
		return 0, false, findings
	}
	result = int64(lo)
	if result == 0 && (a != 0 && b != 0) {
		findings = append(findings, IOVFinding{Reason: IOVReasonMulOverflow})
		return 0, false, findings
	}
	if result == 0 && policy.RejectZero {
		findings = append(findings, IOVFinding{Reason: IOVReasonZeroSize})
		return 0, false, findings
	}
	if result > policy.MaxAllocation {
		findings = append(findings, IOVFinding{Reason: IOVReasonExceedsLimit,
			Detail: iovItoa(result)})
		return result, false, findings
	}
	return result, true, nil
}

// IOVCheckedAdd 计算 offset+delta，带溢出与上限判定。
func IOVCheckedAdd(offset, delta int64, policy IOVPolicy) (result int64, safe bool, findings []IOVFinding) {
	if offset < 0 || delta < 0 {
		findings = append(findings, IOVFinding{Reason: IOVReasonNegativeSize})
		return 0, false, findings
	}
	sum, carry := bits.Add64(uint64(offset), uint64(delta), 0)
	if carry != 0 || sum > uint64(1<<63-1) {
		findings = append(findings, IOVFinding{Reason: IOVReasonAddOverflow})
		return 0, false, findings
	}
	result = int64(sum)
	if result > policy.MaxAllocation {
		findings = append(findings, IOVFinding{Reason: IOVReasonExceedsLimit,
			Detail: iovItoa(result)})
		return result, false, findings
	}
	return result, true, nil
}

// IOVCheckedAlign 把 size 向上对齐到 alignment 的倍数（alignment 为 2 的幂），检查回绕。
func IOVCheckedAlign(size int64, alignment int64, policy IOVPolicy) (result int64, safe bool, findings []IOVFinding) {
	if size < 0 || alignment <= 0 {
		findings = append(findings, IOVFinding{Reason: IOVReasonNegativeSize})
		return 0, false, findings
	}
	if alignment&(alignment-1) != 0 {
		// 非 2 的幂：用普通上取整
		d := size % alignment
		add := int64(0)
		if d != 0 {
			add = alignment - d
		}
		return IOVCheckedAdd(size, add, policy)
	}
	mask := alignment - 1
	add := (alignment - (size & mask)) & mask
	sum, carry := bits.Add64(uint64(size), uint64(add), 0)
	if carry != 0 || sum > uint64(1<<63-1) {
		findings = append(findings, IOVFinding{Reason: IOVReasonAlignOverflow})
		return 0, false, findings
	}
	result = int64(sum)
	if result > policy.MaxAllocation {
		findings = append(findings, IOVFinding{Reason: IOVReasonExceedsLimit,
			Detail: iovItoa(result)})
		return result, false, findings
	}
	return result, true, nil
}

func iovItoa(i int64) string {
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
