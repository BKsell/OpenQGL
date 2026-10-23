package main

// instancenameguard.go —— 实例/世界名转文件系统目录名的净化守卫。
//
// 背景：
//   启动器为每个 Minecraft 实例/世界在磁盘建目录（instances/<名字>、saves/<世界名>）。名字来自
//   用户输入、服务器列表、整合包 metadata，是可控字符串，直接拼进路径会出问题：
//     - 名字里带 ../ 穿越出 instances 根，覆盖其它实例或系统文件；
//     - Windows 非法字符 <>:"/\|?*、保留设备名 CON/PRN/NUL、末尾空格点、NTFS ADS；
//     - 名字为 "."/".."、空串、超长（超 MAX_PATH）；
//     - 同名大小写/Unicode 不同写法（World 与 world、全角字符）造成目录冲突/已存在实例被复用；
//     - 控制字符/零宽字符导致目录不可见或日志注入。
//   pathguard 管的是"通用路径规范化"，本模块专管"名字→单一目录分量"，产出安全分量与冲突键，
//   纯字符处理，不使用正则。

import "strings"

const (
	INGReasonTraversal        = "instancename-path-traversal"
	INGReasonIllegalChar      = "instancename-illegal-filesystem-char"
	INGReasonReservedDevice   = "instancename-windows-reserved-device"
	INGReasonTrailingSpaceDot = "instancename-trailing-space-or-dot"
	INGReasonEmpty            = "instancename-empty"
	INGReasonTooLong          = "instancename-component-too-long"
	INGReasonControlChar      = "instancename-control-character"
	INGReasonDotName          = "instancename-dot-or-dotdot"
	INGReasonLeadingDotHidden = "instancename-leading-dot-unix-hidden"
)

// INGPolicy 设定目录分量策略。
type INGPolicy struct {
	MaxComponentLength int
	ForbidLeadingDot   bool
	Replacement        byte // 非法字符替换为该字节
}

// INGFinding 记录一处名字风险。
type INGFinding struct {
	Reason string
	Detail string
}

// DefaultINGPolicy 给出 Windows 友好的单分量限制（255，留余量给路径前缀）。
func DefaultINGPolicy() INGPolicy {
	return INGPolicy{MaxComponentLength: 200, ForbidLeadingDot: false, Replacement: '_'}
}

var ingReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// INGSanitize 把实例/世界名净化为单一安全目录分量。返回分量、冲突键与风险。
func INGSanitize(name string, policy INGPolicy) (component string, collisionKey string, safe bool, findings []INGFinding) {
	s := name
	if s == "" || strings.TrimSpace(s) == "" {
		return "_unnamed", "_unnamed", false,
			[]INGFinding{{Reason: INGReasonEmpty}}
	}

	// 控制字符
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7F {
			findings = append(findings, INGFinding{Reason: INGReasonControlChar})
			break
		}
	}

	if strings.Contains(s, "..") || strings.ContainsAny(s, `/\`) {
		findings = append(findings, INGFinding{Reason: INGReasonTraversal})
	}

	// 非法字符替换
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch c {
		case '<', '>', ':', '"', '/', '\\', '|', '?', '*':
			findings = append(findings, INGFinding{Reason: INGReasonIllegalChar, Detail: string(c)})
			b[i] = policy.Replacement
		}
		if c < 0x20 || c == 0x7F {
			b[i] = policy.Replacement
		}
	}
	s = string(b)

	if strings.HasSuffix(s, " ") || strings.HasSuffix(s, ".") {
		findings = append(findings, INGFinding{Reason: INGReasonTrailingSpaceDot})
		s = strings.TrimRight(s, " .")
	}
	if policy.ForbidLeadingDot && strings.HasPrefix(s, ".") {
		findings = append(findings, INGFinding{Reason: INGReasonLeadingDotHidden})
	}

	// 去除 ADS 冒号已在上面被替换；再处理纯点名
	if s == "." || s == ".." {
		findings = append(findings, INGFinding{Reason: INGReasonDotName})
		s = strings.ReplaceAll(s, ".", "_")
	}
	if s == "" {
		s = "_unnamed"
		findings = append(findings, INGFinding{Reason: INGReasonEmpty})
	}

	stem := s
	if i := strings.LastIndexByte(stem, '.'); i > 0 {
		stem = stem[:i]
	}
	if ingReserved[strings.ToLower(strings.TrimSpace(stem))] {
		findings = append(findings, INGFinding{Reason: INGReasonReservedDevice, Detail: stem})
		s = "_" + s
	}

	if policy.MaxComponentLength > 0 && len(s) > policy.MaxComponentLength {
		findings = append(findings, INGFinding{Reason: INGReasonTooLong,
			Detail: itoaING(len(s))})
		s = s[:policy.MaxComponentLength]
	}

	// 冲突键：小写折叠，便于检测大小写/同名复用
	return s, strings.ToLower(strings.TrimSpace(s)), len(findings) == 0, findings
}

// INGCollides 判断已存在实例键集合中是否与目标键冲突。
func INGCollides(existing map[string]bool, key string) bool {
	return existing[strings.ToLower(strings.TrimSpace(key))]
}

func itoaING(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
