package main

// filepermsguard.go —— 落盘文件权限位安全（敏感文件不得 group/other 可读可写、目录不得过宽）。
//
// 背景：
//   启动器把会话令牌（账号 JSON）、客户端/服务端配置、下载的 Java、世界存档备份等写入
//   用户目录。若创建时给了过宽权限（0777/0666 或继承了世界可写父目录），同机其它账户、
//   恶意软件或共享主机上的其它进程就能读取令牌、篡改 jar 或配置。Windows 上 Go 的权限位
//   概念弱，但本模块仍按传入的 os.FileMode 做统一裁决，并对"世界可写""组可读敏感文件"
//   给出可移植的风险信号；真正的 ACL 收紧由调用平台落地。
//
// 纯位运算，不读盘。

const (
	FPRReasonWorldWritable    = "fpr-world-writable"
	FPRReasonWorldReadable    = "fpr-world-readable-sensitive"
	FPRReasonGroupWritable    = "fpr-group-writable-sensitive"
	FPRReasonGroupReadable    = "fpr-group-readable-secret"
	FPRReasonExecutableBitSet = "fpr-non-program-executable-bit"
	FPRReasonBadSensitiveMode = "fpr-sensitive-file-mode-too-open"
	FPRReasonDirectoryTooOpen = "fpr-directory-mode-too-open"
)

// 文件敏感级别。
const (
	FPRClassOrdinary = iota // 普通缓存 / 公开资源
	FPRClassConfig          // 配置
	FPRClassSecret          // 令牌 / 凭据
	FPRClassProgram         // 可执行程序（jar/java/exe）
)

// FPRPolicy 控制权限严格度。
type FPRPolicy struct {
	SecretMaxMode       uint32 // 密钥文件允许的最大权限（默认 0600）
	ConfigMaxMode       uint32 // 配置文件允许的最大权限（默认 0640）
	SecretRejectGroup   bool   // 密钥文件拒绝任何 group/other 位
	DirectoryMaxMode    uint32 // 存放敏感文件的目录最大权限（默认 0750）
	RejectWorldWritable bool
}

// FPRFinding 记录一处权限风险。
type FPRFinding struct {
	Reason string
	Class  int
	Mode   uint32
	Detail string
}

// FPREntry 描述一个待写文件 / 目录。
type FPREntry struct {
	Name      string
	Mode      uint32
	Class     int
	IsDir     bool
}

// DefaultFPRPolicy 返回默认严格策略。
func DefaultFPRPolicy() FPRPolicy {
	return FPRPolicy{
		SecretMaxMode:       0600,
		ConfigMaxMode:       0640,
		SecretRejectGroup:   true,
		DirectoryMaxMode:    0750,
		RejectWorldWritable: true,
	}
}

// 权限位常量（八进制语义）。
const (
	fpOtherWrite = 0o002
	fpOtherRead  = 0o004
	fpGroupWrite = 0o020
	fpGroupRead  = 0o040
	fpAnyExecute = 0o111
)

// fprModeTooOpen 判断 mode 是否比 max 多出任何权限位（mode 不是 max 的子集）。
func fprModeTooOpen(mode, max uint32) bool {
	return mode&^max != 0
}

// FPREvaluate 校验单个文件 / 目录的权限位。
func FPREvaluate(e FPREntry, pol FPRPolicy) []FPRFinding {
	var out []FPRFinding
	mode := e.Mode & 0o777 // 只看低 9 位权限，忽略类型 / setuid 高位
	add := func(reason, detail string) {
		out = append(out, FPRFinding{Reason: reason, Class: e.Class, Mode: mode, Detail: detail})
	}

	if pol.RejectWorldWritable && mode&fpOtherWrite != 0 {
		add(FPRReasonWorldWritable, "other-write")
	}

	if e.IsDir {
		if fprModeTooOpen(mode, pol.DirectoryMaxMode) {
			add(FPRReasonDirectoryTooOpen, "dir-exceeds-max")
		}
		return out
	}

	switch e.Class {
	case FPRClassSecret:
		if fprModeTooOpen(mode, pol.SecretMaxMode) {
			add(FPRReasonBadSensitiveMode, "secret-exceeds-0600")
		}
		if pol.SecretRejectGroup {
			if mode&fpGroupRead != 0 {
				add(FPRReasonGroupReadable, "secret-group-read")
			}
			if mode&fpGroupWrite != 0 {
				add(FPRReasonGroupWritable, "secret-group-write")
			}
		}
		if mode&(fpOtherRead|fpOtherWrite) != 0 {
			add(FPRReasonWorldReadable, "secret-other-access")
		}
	case FPRClassConfig:
		if fprModeTooOpen(mode, pol.ConfigMaxMode) {
			add(FPRReasonBadSensitiveMode, "config-exceeds-0640")
		}
		if mode&fpOtherWrite != 0 {
			add(FPRReasonWorldWritable, "config-other-write")
		}
	case FPRClassProgram:
		// 程序文件不应可被组 / 其它用户改写。
		if mode&(fpGroupWrite|fpOtherWrite) != 0 {
			add(FPRReasonGroupWritable, "program-writable-by-nonowner")
		}
	case FPRClassOrdinary:
		if mode&fpOtherWrite != 0 {
			add(FPRReasonWorldWritable, "ordinary-other-write")
		}
	}

	// 非程序文件带任意执行位通常是误配（文本配置 / 令牌不应可执行）。
	if e.Class != FPRClassProgram && mode&fpAnyExecute != 0 {
		add(FPRReasonExecutableBitSet, "unexpected-execute-bit")
	}
	return out
}

// FPREvaluateAll 批量校验。
func FPREvaluateAll(entries []FPREntry, pol FPRPolicy) []FPRFinding {
	var out []FPRFinding
	for _, e := range entries {
		out = append(out, FPREvaluate(e, pol)...)
	}
	return out
}

// FPRSafeModeFor 返回某敏感级别建议使用的创建权限位。
func FPRSafeModeFor(class int, isDir bool) uint32 {
	if isDir {
		return 0o750
	}
	switch class {
	case FPRClassSecret:
		return 0o600
	case FPRClassConfig:
		return 0o640
	case FPRClassProgram:
		return 0o755
	default:
		return 0o644
	}
}

// FPRIsSafe 便捷判定。
func FPRIsSafe(e FPREntry) bool {
	return len(FPREvaluate(e, DefaultFPRPolicy())) == 0
}
