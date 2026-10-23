package main

// assetindexguard.go —— Minecraft assetIndex 资源索引内部一致性与越界守卫。
//
// 背景：
//   资源索引 JSON（objects/<2位哈希>/<完整哈希> 映射 + virtual/map_to_resources 旧版虚拟映射）决定
//   上千个音效/语言/纹理从哪取、放到哪。它本身来自受信主机（manifestpinguard 管来源），但索引内部
//   字段仍可被篡改或本身异常：
//     - 对象路径不匹配其声明哈希：要求 objects/aa/bbcc...，其中前两位必须等于哈希前缀，否则
//       resources.download 的对象寻址与本地缓存键不一致，可被缓存投毒/串档；
//     - 资源相对路径含 .. 或绝对路径（virtual 模式 map_to_resources 会按该名字落盘）→ 穿越；
//     - size 与哈希长度不符/为 0/超过单资源上限（解压/内存放大，intoverflowguard 另管乘法）；
//     - 重复逻辑路径映射到不同哈希（同名资源两个对象，缓存取其一造成差异）；
//     - totalSize 字段与逐项 size 之和不一致（伪造清单大小，绕过容量/进度校验）；
//     - virtual/resources 模式下出现可执行扩展名或 META-INF 路径。
//   Mojang 资产对象用 SHA1，外部校验算法保持原样；本模块只做索引结构一致性，纯字符串/数值判定，
//   不使用正则。

import "strings"

const (
	AIGReasonPathHashMismatch  = "assetindex-object-path-hash-prefix-mismatch"
	AIGReasonTraversalName     = "assetindex-resource-name-path-traversal"
	AIGReasonAbsoluteName      = "assetindex-resource-name-absolute"
	AIGReasonBadObjectHashLen  = "assetindex-object-hash-bad-length"
	AIGReasonBadObjectHashHex  = "assetindex-object-hash-non-hex"
	AIGReasonSizeZeroOrBig     = "assetindex-object-size-zero-or-too-big"
	AIGReasonDuplicateName     = "assetindex-duplicate-resource-name-different-hash"
	AIGReasonTotalSizeMismatch = "assetindex-declared-total-size-mismatch"
	AIGReasonExecutableVirtual = "assetindex-virtual-executable-or-meta-inf"
)

// AIGObject 是一个资源对象。
type AIGObject struct {
	Hash string
	Size int64
	// StoredPath 可选，为实际对象存储相对路径（objects/xx/<hash>）；提供时核对前缀自洽。
	StoredPath string
}

// AIGEntry 是逻辑资源名到对象的映射。
type AIGEntry struct {
	Name   string // 如 minecraft/sounds/xx.ogg，virtual 模式下也是落盘相对路径
	Object AIGObject
}

// AIGIndexView 描述整个索引。
type AIGIndexView struct {
	Entries       []AIGEntry
	DeclaredTotal int64
	Virtual       bool // virtual / map_to_resources 旧版模式
}

// AIGFinding 记录一处索引风险。
type AIGFinding struct {
	Reason string
	Detail string
}

const aigMaxObjectSize = 256 * 1024 * 1024 // 单资源 256MiB 上限

func aigIsLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// AIGValidate 校验整个资源索引。
func AIGValidate(v AIGIndexView) (safe bool, findings []AIGFinding) {
	add := func(reason, detail string) {
		findings = append(findings, AIGFinding{Reason: reason, Detail: detail})
	}

	nameToHash := map[string]string{}
	var sum int64
	sumOverflow := false

	for _, e := range v.Entries {
		name := strings.ReplaceAll(e.Name, "\\", "/")
		hash := strings.TrimSpace(e.Object.Hash)

		// 哈希：Mojang 对象键为 40 位小写十六进制 SHA1
		hashOK := len(hash) == 40
		if !hashOK {
			add(AIGReasonBadObjectHashLen, name)
		} else if !aigIsLowerHex(hash) {
			add(AIGReasonBadObjectHashHex, name)
		} else if sp := strings.TrimSpace(e.Object.StoredPath); sp != "" {
			// 对象存储路径必须是 objects/<前2位>/<完整哈希>，前缀错即寻址/缓存键不一致
			want := "objects/" + hash[:2] + "/" + hash
			if strings.ReplaceAll(sp, "\\", "/") != want {
				add(AIGReasonPathHashMismatch, sp+"!="+want)
			}
		}

		// 逻辑名穿越/绝对
		if strings.Contains(name, "..") {
			add(AIGReasonTraversalName, name)
		}
		if strings.HasPrefix(name, "/") {
			add(AIGReasonAbsoluteName, name)
		}
		lowerName := strings.ToLower(name)
		if len(lowerName) >= 2 && name[1] == ':' {
			add(AIGReasonAbsoluteName, name)
		}

		// 大小
		if e.Object.Size <= 0 {
			add(AIGReasonSizeZeroOrBig, name+":zero")
		} else if e.Object.Size > aigMaxObjectSize {
			add(AIGReasonSizeZeroOrBig, name+":big")
		}

		// 累计 totalSize，防溢出
		if !sumOverflow {
			sum += e.Object.Size
			if sum < e.Object.Size {
				sumOverflow = true
			}
		}

		// 同名不同哈希
		if prior, ok := nameToHash[name]; ok {
			if prior != hash {
				add(AIGReasonDuplicateName, name)
			}
		}
		nameToHash[name] = hash

		// virtual 落盘模式下的可执行/META-INF
		if v.Virtual {
			base := lowerName
			if i := strings.LastIndexByte(base, '/'); i >= 0 {
				base = base[i+1:]
			}
			for _, ext := range []string{".exe", ".dll", ".bat", ".cmd", ".sh", ".jar"} {
				if strings.HasSuffix(base, ext) {
					add(AIGReasonExecutableVirtual, name)
					break
				}
			}
			if strings.HasPrefix(lowerName, "meta-inf/") {
				add(AIGReasonExecutableVirtual, name)
			}
		}
	}

	if v.DeclaredTotal > 0 || sum > 0 {
		if sumOverflow || v.DeclaredTotal != sum {
			add(AIGReasonTotalSizeMismatch, aigItoaSum(v.DeclaredTotal)+"!="+aigItoaSum(sum))
		}
	}
	return len(findings) == 0, findings
}

// AIGObjectPath 返回某哈希对应的对象存储相对路径（objects/xx/<hash>）。
func AIGObjectPath(hash string) string {
	if len(hash) < 2 {
		return ""
	}
	return "objects/" + hash[:2] + "/" + hash
}

func aigItoaSum(i int64) string {
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
