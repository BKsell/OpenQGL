package main

// envpathoverridedirectoryguard.go —— 动态库/解释器劫持环境变量目录。
//
// 威胁模型：
//   LD_PRELOAD/LD_LIBRARY_PATH/DYLD_INSERT_LIBRARIES/NODE_OPTIONS/PYTHONPATH 可加载恶意库或插桩，
//   启动子进程前应清空。纯字符查表，不用正则。

const (
	EPOClassBlock   = "block"
	EPOClassWarn    = "warn"
	EPOClassAllow   = "allow"
	EPOClassUnknown = "unknown"
)

var EPOBlock = []string{
	"ld_preload",
	"ld_library_path",
	"dyld_insert_libraries",
	"node_options",
	"pythonpath",
	"node_extra_ca_certs",
}

var EPOWarn = []string{
	"path",
	"perl5lib",
}

var EPOAllow = []string{
	"tz",
	"lang",
	"lc_all",
}

func EPOLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func EPOIn(list []string, v string) bool {
	for _, x := range list { if EPOLower(x) == v { return true } }
	return false
}

// EPOClassify 分类单个令牌。
func EPOClassify(tok string) string {
	v := EPOLower(tok)
	switch {
	case EPOIn(EPOBlock, v): return EPOClassBlock
	case EPOIn(EPOWarn, v): return EPOClassWarn
	case EPOIn(EPOAllow, v): return EPOClassAllow
	default: return EPOClassUnknown
	}
}
