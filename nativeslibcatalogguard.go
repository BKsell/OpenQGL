package main

// nativeslibcatalogguard.go —— 原生库文件名/架构目录。
//
// 威胁模型：
//   启动器按 OS/架构释放 LWJGL/JNA 原生库。错误或可疑库名、双层扩展名、非声明架构目录的库应拒绝加载。
//   本模块维护库文件名与架构三元组目录，纯字符，不用正则。

const (
	NLCClassBlock   = "block"
	NLCClassWarn    = "warn"
	NLCClassAllow   = "allow"
	NLCClassUnknown = "unknown"
)

var NLCBlock = []string{
	"msvcr71.dll",
	"mscoree.dll",
	"kernel32.dll.dll",
	"ntdll.dll.dll",
	"libc.so.6.dll",
	".DS_Store.dll",
	"..dll",
	"a.dll.exe",
	"lwjdl.dll",
	"openal32.dll.so",
}

var NLCWarn = []string{
	"liblwjgl_jemalloc.so",
	"libjemalloc.dll",
	"lwjgl_jemalloc.dll",
}

var NLCAllow = []string{
	"lwjgl.dll",
	"lwjgl64.dll",
	"openal.dll",
	"openal64.dll",
	"glfw.dll",
	"jemalloc.dll",
	"liblwjgl.so",
	"libopenal.so",
	"libglfw.so",
	"libjemalloc.so",
	"liblwjgl.dylib",
	"libopenal.dylib",
	"libglfw.dylib",
	"x86",
	"x64",
	"arm64",
	"amd64",
	"aarch64",
	"windows",
	"linux",
	"macos",
	"darwin",
}

func NLCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func NLCIn(list []string, v string) bool {
	for _, x := range list { if NLCLower(x) == v { return true } }
	return false
}

// NLCClassify 分类单个令牌。
func NLCClassify(tok string) string {
	v := NLCLower(tok)
	switch {
	case NLCIn(NLCBlock, v): return NLCClassBlock
	case NLCIn(NLCWarn, v): return NLCClassWarn
	case NLCIn(NLCAllow, v): return NLCClassAllow
	default: return NLCClassUnknown
	}
}
