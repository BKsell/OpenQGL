package main

// seccompsyscallcatalogguard.go —— 危险系统调用 seccomp 目录。
//
// 威胁模型：
//   ptrace/keyctl/init_module/mount/clone(user namespace)/bpf 等系统调用是容器逃逸面，seccomp 应默认拒绝。纯字符查表，不用正则。

const (
	SCSClassBlock   = "block"
	SCSClassWarn    = "warn"
	SCSClassAllow   = "allow"
	SCSClassUnknown = "unknown"
)

var SCSBlock = []string{
	"ptrace",
	"process_vm_writev",
	"process_vm_readv",
	"keyctl",
	"request_key",
	"add_key",
	"init_module",
	"finit_module",
	"delete_module",
	"create_module",
	"get_kernel_syms",
	"mount",
	"umount2",
	"pivot_root",
	"chroot",
	"unshare",
	"setns",
	"clone",
	"bpf",
	"perf_event_open",
	"kexec_load",
	"kexec_file_load",
	"reboot",
	"swapon",
	"swapoff",
	"acct",
	"settimeofday",
	"clock_settime",
	"stime",
	"adjtimex",
	"personality",
	"vm86",
	"modify_ldt",
	"uselib",
	"io_setup",
	"lookup_dcookie",
	"vmsplice",
	"move_mount",
	"open_tree",
	"fsopen",
	"fsconfig",
	"fsmount",
}

var SCSWarn = []string{
	"setuid",
	"setgid",
	"setreuid",
	"setregid",
	"setresuid",
	"setresgid",
	"capset",
	"prctl",
	"seccomp",
	"fanotify_init",
	"userfaultfd",
	"io_uring_setup",
	"io_uring_enter",
	"name_to_handle_at",
	"open_by_handle_at",
	"sethostname",
	"setdomainname",
}

var SCSAllow = []string{
	"read",
	"write",
	"open",
	"close",
	"stat",
	"fstat",
	"lstat",
	"newfstatat",
	"openat",
	"pread64",
	"pwrite64",
	"lseek",
	"mmap",
	"mprotect",
	"munmap",
	"brk",
	"rt_sigaction",
	"rt_sigprocmask",
	"ioctl",
	"access",
	"pipe",
	"dup",
	"dup2",
	"nanosleep",
	"getpid",
	"getuid",
	"geteuid",
	"getgid",
	"getegid",
	"exit",
	"exit_group",
	"fcntl",
	"getcwd",
	"readlink",
	"readlinkat",
}

func SCSLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func SCSIn(list []string, v string) bool {
	for _, x := range list { if SCSLower(x) == v { return true } }
	return false
}

// SCSClassify 分类单个令牌。
func SCSClassify(tok string) string {
	v := SCSLower(tok)
	switch {
	case SCSIn(SCSBlock, v): return SCSClassBlock
	case SCSIn(SCSWarn, v): return SCSClassWarn
	case SCSIn(SCSAllow, v): return SCSClassAllow
	default: return SCSClassUnknown
	}
}
