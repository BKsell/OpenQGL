package main

// filepermguard.go —— 落盘敏感文件/目录的权限位（ACL）守卫。
//
// 背景：
//   启动器把账号令牌、客户端配置、会话、备份写在用户目录。文件权限决定"本机其它账户能否读到/
//   改掉"这些内容：
//     - token/config/备份文件权限宽于属主（group/other 可读），同机其它用户直接窃取令牌；
//     - 目录对 group/other 可写，可在其中放入/替换文件（即使文件本身 0600，也能新建恶意文件）；
//     - 文件对其它人可写，可被直接篡改（改下载基址、关掉校验、塞入 javaagent 路径）；
//     - setuid/setgid/sticky 异常位、Windows 上继承了过宽 ACL（Everyone/Users 可写）；
//     - 属主不是当前用户（root 拥有但 0666，或属主为其它账户）。
//   tokenstoreguard 管"令牌该不该落盘、有没有副本"，本模块管"已落盘文件/目录的具体权限位"，
//   权限位为调用方从 os.Stat/ACL 读取后填入，纯位运算判定，不使用正则。

const (
	FPMReasonWorldReadable    = "fileperm-world-readable-sensitive-file"
	FPMReasonWorldWritable    = "fileperm-world-writable"
	FPMReasonGroupReadable    = "fileperm-group-readable-sensitive-file"
	FPMReasonGroupWritable    = "fileperm-group-writable"
	FPMReasonDirWorldWritable = "fileperm-directory-world-or-group-writable"
	FPMReasonSetuidSetgid     = "fileperm-setuid-setgid-bit-on-data-file"
	FPMReasonForeignOwner     = "fileperm-owner-not-current-user"
	FPMReasonWindowsWeakACL   = "fileperm-windows-acl-grants-users-or-everyone-write"
)

// FPMSensitiveKind 标记文件敏感级别。
type FPMSensitiveKind int

const (
	FPMKindNormal FPMSensitiveKind = iota
	FPMKindConfig
	FPMKindToken
	FPMKindPrivateKey
)

// FPMView 描述一个落盘对象的权限视图（跨平台归一）。
type FPMView struct {
	Path           string
	IsDir          bool
	ModePerm       uint32 // 低 9 位 + setuid/setgid/sticky
	OwnerIsCurrent bool
	Sensitive      FPMSensitiveKind
	WindowsWeakACL bool // Everyone/Users/Authenticated Users 有写/改权限
}

// FPMFinding 记录一处权限风险。
type FPMFinding struct {
	Reason string
	Path   string
	Detail string
}

// FPMRecommendedPerm 返回不同敏感级别建议的最大权限位。
func FPMRecommendedPerm(kind FPMSensitiveKind) uint32 {
	switch kind {
	case FPMKindPrivateKey, FPMKindToken:
		return 0600
	case FPMKindConfig:
		return 0640
	default:
		return 0644
	}
}

const (
	fpmWorldR = uint32(0004)
	fpmWorldW = uint32(0002)
	fpmWorldX = uint32(0001)
	fpmGroupR = uint32(0040)
	fpmGroupW = uint32(0020)
	fpmSetuid = uint32(04000)
	fpmSetgid = uint32(02000)
)

// FPMEvaluate 审计单个对象权限。
func FPMEvaluate(v FPMView) (safe bool, findings []FPMFinding) {
	add := func(reason, detail string) {
		findings = append(findings, FPMFinding{Reason: reason, Path: v.Path, Detail: detail})
	}

	if v.ModePerm&fpmSetuid != 0 || v.ModePerm&fpmSetgid != 0 {
		add(FPMReasonSetuidSetgid, fpmOctal(v.ModePerm))
	}
	if v.ModePerm&fpmWorldW != 0 {
		add(FPMReasonWorldWritable, "o+w")
	}
	if v.ModePerm&fpmGroupW != 0 {
		if v.IsDir {
			add(FPMReasonDirWorldWritable, "g+w-dir")
		} else {
			add(FPMReasonGroupWritable, "g+w")
		}
	}
	if v.IsDir && v.ModePerm&fpmWorldW != 0 {
		add(FPMReasonDirWorldWritable, "o+w-dir")
	}

	if v.Sensitive != FPMKindNormal {
		if v.ModePerm&fpmWorldR != 0 {
			add(FPMReasonWorldReadable, "o+r")
		}
		if v.ModePerm&fpmGroupR != 0 && (v.Sensitive == FPMKindToken ||
			v.Sensitive == FPMKindPrivateKey) {
			add(FPMReasonGroupReadable, "g+r")
		}
		// 与建议上限比对
		cap := FPMRecommendedPerm(v.Sensitive)
		if v.ModePerm&uint32(0777)&^cap != 0 {
			add(FPMReasonGroupReadable, "exceeds-recommended-"+fpmOctal(cap))
		}
	}

	if !v.OwnerIsCurrent {
		add(FPMReasonForeignOwner, "owner")
	}
	if v.WindowsWeakACL {
		add(FPMReasonWindowsWeakACL, "acl")
	}
	return len(findings) == 0, findings
}

// FPMEvaluateAll 批量审计。
func FPMEvaluateAll(views []FPMView) (safe bool, all []FPMFinding) {
	for _, v := range views {
		_, fs := FPMEvaluate(v)
		all = append(all, fs...)
	}
	return len(all) == 0, all
}

func fpmOctal(m uint32) string {
	if m == 0 {
		return "0"
	}
	var b []byte
	for shift := 12; shift >= 0; shift -= 3 {
		b = append(b, byte('0'+(m>>uint(shift))&7))
	}
	out := trimLeftZeroFPM(string(b))
	return out
}

func trimLeftZeroFPM(s string) string {
	i := 0
	for i < len(s)-1 && s[i] == '0' {
		i++
	}
	return s[i:]
}
