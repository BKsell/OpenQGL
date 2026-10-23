package main

// archivemembernamecatalogguard.go —— 压缩包成员危险名称目录。
//
// 威胁模型：
//   ../、绝对路径、盘符与可执行/脚本扩展名成员可致 Zip Slip 落地到敏感目录，解包前按成员名阻断。纯字符查表，不用正则。

const (
	ARMClassBlock   = "block"
	ARMClassWarn    = "warn"
	ARMClassAllow   = "allow"
	ARMClassUnknown = "unknown"
)

var ARMBlock = []string{
	"../",
	"..\\",
	"/../",
	"\\..\\",
	".pif",
	".scr",
	".bat",
	".cmd",
	".com",
	".lnk",
	".exe",
	".dll",
	".so",
	".dylib",
	".sh",
	".run",
	".bin",
	".elf",
	".app",
	".ps1",
	".vbs",
	".jar",
}

var ARMWarn = []string{
	"autorun.inf",
	"Thumbs.db",
	"desktop.ini",
	".htaccess",
	".htpasswd",
	"web.config",
	"__MACOSX",
	".git",
	".svn",
	".DS_Store",
}

var ARMAllow = []string{
	".json",
	".txt",
	".png",
	".jpg",
	".jpeg",
	".webp",
	".md",
	".toml",
	".yml",
	".yaml",
	".css",
}

func ARMLower(x string) string {
	return x
}

func ARMIn(list []string, v string) bool {
	for _, x := range list { if ARMLower(x) == v { return true } }
	return false
}

// ARMClassify 分类单个令牌。
func ARMClassify(tok string) string {
	v := ARMLower(tok)
	switch {
	case ARMIn(ARMBlock, v): return ARMClassBlock
	case ARMIn(ARMWarn, v): return ARMClassWarn
	case ARMIn(ARMAllow, v): return ARMClassAllow
	default: return ARMClassUnknown
	}
}
