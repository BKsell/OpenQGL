package main

// versionsguard：versions/<id>/<id>.json 结构守卫。
//
// 版本 JSON 由外部来源（官方/镜像/第三方启动器导出的实例）落入磁盘，
// 加载器在拼 classpath 之前会读它的 id / jar / inheritsFrom / libraries /
// downloads 字段。若文件被篡改或损坏（例如 jar 字段写成
// "versions/1.20/../../../evil.jar"，inheritsFrom 指到不存在的 id 或成环），
// 轻则加载失败，重则把任意路径塞进 -cp。gameclasspath 在“最终条目”层面
// 做绝对路径验收，这里在“源头字段”层面提前拦截，两道防线互补。
//
// 校验内容：
//   - id 必须等于所在目录名，且不含路径分隔符 / 控制字符；
//   - jar / downloads 路径必须以 versions/<id>/ 为前缀，且相对路径干净
//     （无绝对路径、无 ".." 段、无空段、无反斜杠、无控制字符、段数与长度有界）；
//   - inheritsFrom 单值、无分隔符，继承链深度有界且不成环（对已知版本集合校验）；
//   - libraries 数量有界，Maven 坐标分段合法，artifact path 与 natives 值无穿越；
//   - assetIndex.id 无分隔符。
// 外部 API 哈希（Mojang SHA1 / authlib SHA256 / Modrinth sha1/sha512）不属于
// 本模块——版本 JSON 的 downloads/artifact 只做路径与结构校验，不碰哈希算法。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// VersionJSONLimits 版本 JSON 校验的量化边界（防止畸变文件耗尽资源）。
type VersionJSONLimits struct {
	MaxIDLen      int // id / inheritsFrom 单值长度
	MaxPathSegs   int // 相对路径最大段数
	MaxPathLen    int // 相对路径总长
	MaxLibraries  int // libraries 数组条数上限
	MaxInheritDep int // 继承链最大深度
	MaxJSONBytes  int64
}

func defaultVersionJSONLimits() VersionJSONLimits {
	return VersionJSONLimits{
		MaxIDLen:      64,
		MaxPathSegs:   8,
		MaxPathLen:    512,
		MaxLibraries:  2000,
		MaxInheritDep: 8,
		MaxJSONBytes:  4 << 20,
	}
}

type versionVerdict struct {
	OK     bool
	Reason string
}

// validateVersionRelPath 校验版本 JSON 内部出现的相对路径：必须相对、干净、
// 段数与长度有界。prefix（如 "versions/1.20/"）存在时要求路径以此为前缀，
// 防止 jar 字段指向 libraries 或任意目录。
func validateVersionRelPath(p, prefix string, lim VersionJSONLimits) string {
	if p == "" {
		return "empty-path"
	}
	if len(p) > lim.MaxPathLen {
		return "path-too-long"
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") || filepath.IsAbs(p) {
		return "absolute-path"
	}
	if strings.ContainsAny(p, "\x00\r\n\t") {
		return "control-char"
	}
	if strings.Contains(p, "\\") {
		return "backslash-path"
	}
	segs := strings.Split(p, "/")
	if len(segs) > lim.MaxPathSegs {
		return "too-many-segments"
	}
	for _, seg := range segs {
		if seg == "" {
			return "empty-segment"
		}
		if seg == ".." {
			return "dotdot-segment"
		}
		if seg == "." {
			return "dot-segment"
		}
	}
	if prefix != "" {
		if p == prefix || strings.HasPrefix(p, prefix) {
			return ""
		}
		if strings.HasPrefix(p, prefix) && !strings.HasPrefix(p, prefix+"/") {
			// 前缀按段匹配：prefix 自身以 "/" 结尾时上面分支已覆盖
		}
		if !strings.HasPrefix(p, prefix) {
			return "outside-prefix"
		}
	}
	return ""
}

// validateVersionID 校验单值版本 id：无分隔符、无控制字符、长度有界。
func validateVersionID(id string, lim VersionJSONLimits) string {
	if id == "" {
		return "empty-id"
	}
	if len(id) > lim.MaxIDLen {
		return "id-too-long"
	}
	if strings.ContainsAny(id, "/\\\x00\r\n\t") {
		return "id-separator"
	}
	if id == "." || id == ".." {
		return "id-dot"
	}
	return ""
}

// validateMavenCoordinate 校验 Maven 坐标 group:artifact:version[:classifier]：
// 冒号分段 3~4 段，每段无路径成分与控制字符。
func validateMavenCoordinate(name string, lim VersionJSONLimits) string {
	if name == "" {
		return "empty-name"
	}
	if len(name) > lim.MaxPathLen {
		return "name-too-long"
	}
	if strings.ContainsAny(name, "/\\\x00\r\n\t") {
		return "name-separator"
	}
	parts := strings.Split(name, ":")
	if len(parts) < 3 || len(parts) > 4 {
		return "name-parts"
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "name-part-empty"
		}
	}
	return ""
}

// ValidateVersionJSON 校验单条版本 JSON（dirID 是所在目录名，须与 id 一致）。
func ValidateVersionJSON(v *VersionJSON, dirID string, lim VersionJSONLimits) versionVerdict {
	if v == nil {
		return versionVerdict{false, "nil-json"}
	}
	if r := validateVersionID(v.ID, lim); r != "" {
		return versionVerdict{false, "id:" + r}
	}
	if v.ID != dirID {
		return versionVerdict{false, "id-mismatch-dir"}
	}
	jarPrefix := "versions/" + v.ID + "/"
	if v.Jar != "" {
		if r := validateVersionRelPath(v.Jar, jarPrefix, lim); r != "" {
			return versionVerdict{false, "jar:" + r}
		}
	}
	if v.InheritsFrom != "" {
		if r := validateVersionID(v.InheritsFrom, lim); r != "" {
			return versionVerdict{false, "inherits:" + r}
		}
		if v.InheritsFrom == v.ID {
			return versionVerdict{false, "inherits-self"}
		}
	}
	if v.Libraries != nil {
		if len(v.Libraries) > lim.MaxLibraries {
			return versionVerdict{false, "libraries-overflow"}
		}
		for i, lib := range v.Libraries {
			if r := validateMavenCoordinate(lib.Name, lim); r != "" {
				return versionVerdict{false, "lib-name:" + r + ":" + strconv.Itoa(i)}
			}
			if lib.Downloads != nil {
				if a := lib.Downloads.Artifact; a != nil && a.Path != "" {
					if r := validateVersionRelPath(a.Path, "libraries/", lim); r != "" {
						return versionVerdict{false, "lib-artifact:" + r + ":" + strconv.Itoa(i)}
					}
				}
				for cls, art := range lib.Downloads.Classifiers {
					if art != nil && art.Path != "" {
						if r := validateVersionRelPath(art.Path, "libraries/", lim); r != "" {
							return versionVerdict{false, "lib-classifier:" + r + ":" + cls}
						}
					}
				}
			}
			for cls, val := range lib.Natives {
				if val != "" {
					if r := validateVersionRelPath(val, "", lim); r != "" {
						return versionVerdict{false, "natives:" + r + ":" + cls}
					}
				}
			}
		}
	}
	if v.Downloads != nil {
		for key, art := range map[string]*LibArtifact{
			"client": v.Downloads.Client,
			"server": v.Downloads.Server,
		} {
			if art != nil && art.Path != "" {
				if r := validateVersionRelPath(art.Path, jarPrefix, lim); r != "" {
					return versionVerdict{false, "downloads:" + key + ":" + r}
				}
			}
		}
	}
	if v.AssetIndex != nil {
		if r := validateVersionID(v.AssetIndex.ID, lim); r != "" {
			return versionVerdict{false, "asset-index:" + r}
		}
	}
	return versionVerdict{true, ""}
}

// CheckInheritChain 校验继承链：深度有界、不成环。known 返回某 id 是否
// 存在于版本集合；链上每个节点都必须已知，缺 id 直接判坏。
func CheckInheritChain(start string, known func(string) bool, lim VersionJSONLimits) versionVerdict {
	if start == "" {
		return versionVerdict{true, ""}
	}
	cur := start
	seen := map[string]bool{}
	for depth := 0; depth <= lim.MaxInheritDep; depth++ {
		if seen[cur] {
			return versionVerdict{false, "inherit-cycle:" + cur}
		}
		seen[cur] = true
		if !known(cur) {
			return versionVerdict{false, "inherit-missing:" + cur}
		}
		next := inheritParent(cur)
		if next == "" {
			return versionVerdict{true, ""}
		}
		cur = next
	}
	return versionVerdict{false, "inherit-depth"}
}

// inheritParent 从版本目录内读取 <id>.json 取 inheritsFrom（仅用于链校验，
// 文件由调用方确保在 versions/ 下）。
func inheritParent(id string) string {
	v, err := readVersionJSONForChain(id)
	if err != nil {
		return ""
	}
	return v.InheritsFrom
}

// readVersionJSONForChain 读取 versions/<id>/<id>.json 的 inheritsFrom（仅用于
// 链校验，路径由调用方保证在 versions/ 下）。var 形式便于测试注入假数据。
var readVersionJSONForChain = func(id string) (*VersionJSON, error) {
	p := filepath.Join("versions", id, id+".json")
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var v VersionJSON
	if err := json.NewDecoder(f).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

// CheckVersionsDir 扫描 versions/ 下全部 <id>/<id>.json 做结构校验，
// 返回坏项清单（id -> 原因）。这是加载器侧的实际集成入口。
func CheckVersionsDir(versionsRoot string, lim VersionJSONLimits) []string {
	bad := []string{}
	if lim == (VersionJSONLimits{}) {
		lim = defaultVersionJSONLimits()
	}
	entries, err := os.ReadDir(versionsRoot)
	if err != nil {
		return []string{"scan:" + err.Error()}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if r := validateVersionID(id, lim); r != "" {
			bad = append(bad, id+":"+r)
			continue
		}
		jsonPath := filepath.Join(versionsRoot, id, id+".json")
		info, err := os.Stat(jsonPath)
		if err != nil {
			bad = append(bad, id+":missing-json")
			continue
		}
		if info.Size() > lim.MaxJSONBytes {
			bad = append(bad, id+":json-too-large")
			continue
		}
		raw, err := os.ReadFile(jsonPath)
		if err != nil {
			bad = append(bad, id+":read-json")
			continue
		}
		var v VersionJSON
		if err := json.Unmarshal(raw, &v); err != nil {
			bad = append(bad, id+":unmarshal")
			continue
		}
		if vd := ValidateVersionJSON(&v, id, lim); !vd.OK {
			bad = append(bad, id+":"+vd.Reason)
		}
	}
	return bad
}

// SummarizeVersionVerdict 把校验结果压成一行可读文本（日志/审计事件用）。
func SummarizeVersionVerdict(bad []string) string {
	if len(bad) == 0 {
		return "versions-guard clean"
	}
	return "versions-guard bad=" + strconv.Itoa(len(bad)) + " first=" + bad[0]
}
