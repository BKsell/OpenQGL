package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// resourcepackguard.go —— 资源包 / 数据包 zip 只读预检内核。
//
// 资源包（resource pack / data pack）与 mod 一样来自第三方下载，解压后会被
// 客户端整体读取（assets、data、models、textures）。恶意包在 zip 里塞的条目
// 可能落在解压目录之外（Zip Slip）、伪装成符号链接 / 设备文件、或做成 zip bomb
// 撑爆磁盘；pack.mcmeta 的 JSON 也可能畸形到拖垮解析器。
//
// 本内核只做“预检不改盘”：打开 zip、逐条审路径 / 类型 / 大小、校验
// pack.mcmeta 的字段类型与长度上限，输出一份能否安全安装的裁决。真正的解压
// 落地仍走 zipextract.go 的安全路径（路径归一、类型拒绝、限额）——预检与
// 落地是两道独立防线，不是彼此替代。

// ResourcePackLimits 是资源包安装的规模上限（防 zip bomb 与 inode 耗尽）。
type ResourcePackLimits struct {
	EntryMaxBytes int64
	TotalMaxBytes int64
	MaxEntries    int
	McmetaBytes   int
	PackFormatMin int
	PackFormatMax int
	DescRunes     int
}

func defaultResourcePackLimits() ResourcePackLimits {
	return ResourcePackLimits{
		EntryMaxBytes: 64 * 1024 * 1024, // 单条目 64 MiB
		TotalMaxBytes: 512 * 1024 * 1024, // 总量 512 MiB
		MaxEntries:    20000,
		McmetaBytes:   256 * 1024,
		PackFormatMin: 1,
		PackFormatMax: 999,
		DescRunes:     4096,
	}
}

func normalizeResourcePackLimits(l ResourcePackLimits) ResourcePackLimits {
	d := defaultResourcePackLimits()
	if l.EntryMaxBytes <= 0 || l.EntryMaxBytes > d.EntryMaxBytes {
		l.EntryMaxBytes = d.EntryMaxBytes
	}
	if l.TotalMaxBytes <= 0 || l.TotalMaxBytes > d.TotalMaxBytes {
		l.TotalMaxBytes = d.TotalMaxBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.McmetaBytes <= 0 {
		l.McmetaBytes = d.McmetaBytes
	}
	if l.PackFormatMin <= 0 {
		l.PackFormatMin = d.PackFormatMin
	}
	if l.PackFormatMax < l.PackFormatMin {
		l.PackFormatMax = d.PackFormatMax
	}
	if l.DescRunes <= 0 {
		l.DescRunes = d.DescRunes
	}
	if l.EntryMaxBytes > l.TotalMaxBytes {
		l.EntryMaxBytes = l.TotalMaxBytes
	}
	return l
}

// PackFinding 是资源包预检的单项问题。
type PackFinding struct {
	Severity string // "error"（不可安装）| "warn"（提示）
	Path     string
	Reason   string
}

// PackVerdict 是一次资源包预检的结果。
type PackVerdict struct {
	OK            bool
	Findings      []PackFinding
	EntryCount    int
	TotalBytes    int64
	HasMcmeta     bool
	PackFormat    int
	PackDesc      string
	McmetaMissing bool
}

// classifyZipEntryType 识别 zip 条目的外部类型：常规文件之外的符号链接 /
// 设备等在解压后会变成非普通文件，必须单独标记。
func classifyZipEntryType(f *zip.File) string {
	mode := f.Mode()
	if mode&os.ModeSymlink != 0 {
		return "symlink"
	}
	if mode&os.ModeDevice != 0 || mode&os.ModeCharDevice != 0 || mode&os.ModeNamedPipe != 0 {
		return "device"
	}
	if mode&os.ModeDir != 0 || strings.HasSuffix(f.Name, "/") {
		return "dir"
	}
	return "file"
}

// validateMcmeta 校验 pack.mcmeta：pack_format 必须是有限整数且在可接受范围，
// description 长度受限（防止解析器被超长字符串拖垮）。整份文件大小有上限。
func validateMcmeta(data []byte, l ResourcePackLimits) (format int, desc string, findings []PackFinding) {
	if len(data) > l.McmetaBytes {
		findings = append(findings, PackFinding{
			Severity: "error", Path: "pack.mcmeta",
			Reason: fmt.Sprintf("pack.mcmeta 超过 %d 字节上限", l.McmetaBytes),
		})
		return 0, "", findings
	}
	var meta struct {
		Pack struct {
			PackFormat  json.Number `json:"pack_format"`
			Description interface{} `json:"description"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		findings = append(findings, PackFinding{
			Severity: "error", Path: "pack.mcmeta",
			Reason: "pack.mcmeta 不是合法 JSON",
		})
		return 0, "", findings
	}
	if meta.Pack.PackFormat == "" {
		findings = append(findings, PackFinding{
			Severity: "error", Path: "pack.mcmeta",
			Reason: "缺少 pack.pack_format（整数）",
		})
	} else {
		format = int(packFormatNumber(meta.Pack.PackFormat))
		if format < l.PackFormatMin || format > l.PackFormatMax {
			findings = append(findings, PackFinding{
				Severity: "warn", Path: "pack.mcmeta",
				Reason: fmt.Sprintf("pack_format=%d 超出本启动器支持范围 [%d,%d]", format, l.PackFormatMin, l.PackFormatMax),
			})
		}
	}
	if meta.Pack.Description != nil {
		switch v := meta.Pack.Description.(type) {
		case string:
			desc = v
		default:
			// description 可以是字符串或字符串数组（translate 形式）；非字符串
			// 类型统一做 JSON 化截断，避免下游对未知类型 panic。
			b, _ := json.Marshal(v)
			desc = string(b)
		}
		if len([]rune(desc)) > l.DescRunes {
			findings = append(findings, PackFinding{
				Severity: "error", Path: "pack.mcmeta",
				Reason: fmt.Sprintf("description 超过 %d 个字符上限", l.DescRunes),
			})
		}
	}
	return format, desc, findings
}

// packFormatNumber 把 json.Number 收敛成 int；非整数（小数/NaN 之类）按 0 处理，
// 由调用方判定格式非法。
func packFormatNumber(n json.Number) int {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		var i int
		if _, err := fmt.Sscanf(s, "%d", &i); err == nil {
			return i
		}
	}
	return 0
}

// inspectResourcePackZip 打开并预检一个资源包 zip。zipPath 必须已存在且为普通
// 文件。返回裁决与统计；绝不对磁盘做任何写入。
func inspectResourcePackZip(zipPath string, l ResourcePackLimits) PackVerdict {
	v := PackVerdict{}
	l = normalizeResourcePackLimits(l)
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		v.Findings = append(v.Findings, PackFinding{
			Severity: "error", Path: "$", Reason: fmt.Sprintf("无法打开资源包 zip：%v", err),
		})
		v.OK = false
		return v
	}
	defer zr.Close()

	hasMcmeta := false
	for _, f := range zr.File {
		name := f.Name
		// zip 内统一用 / 分隔；条目名可能是绝对路径或含反斜杠，secureZipRelPath
		// 会做归一化判定，这里先按原始名识别 pack.mcmeta（仅允许根级）。
		if strings.HasSuffix(name, "/") {
			continue
		}
		cleanName := name
		if i := strings.LastIndex(cleanName, "/"); i >= 0 {
			cleanName = cleanName[i+1:]
		}
		if cleanName == "pack.mcmeta" && !strings.Contains(name, "../") {
			hasMcmeta = true
		}
		v.EntryCount++
		if v.EntryCount > l.MaxEntries {
			v.Findings = append(v.Findings, PackFinding{
				Severity: "error", Path: name,
				Reason: fmt.Sprintf("条目数超过 %d 上限", l.MaxEntries),
			})
			v.OK = false
			break
		}
		rel, ok := secureZipRelPath(name)
		if !ok {
			v.Findings = append(v.Findings, PackFinding{
				Severity: "error", Path: name, Reason: "条目路径含穿越/盘符/反斜杠等非法成分",
			})
			v.OK = false
			continue
		}
		switch classifyZipEntryType(f) {
		case "symlink":
			v.Findings = append(v.Findings, PackFinding{
				Severity: "error", Path: rel, Reason: "符号链接条目不允许出现在资源包",
			})
			v.OK = false
		case "device":
			v.Findings = append(v.Findings, PackFinding{
				Severity: "error", Path: rel, Reason: "设备/管道条目不允许出现在资源包",
			})
			v.OK = false
		}
		if f.UncompressedSize64 > uint64(l.EntryMaxBytes) {
			v.Findings = append(v.Findings, PackFinding{
				Severity: "error", Path: rel,
				Reason: fmt.Sprintf("单条目 %d 字节超过 %d 上限", f.UncompressedSize64, l.EntryMaxBytes),
			})
			v.OK = false
		}
		v.TotalBytes += int64(f.UncompressedSize64)
		if v.TotalBytes > l.TotalMaxBytes {
			v.Findings = append(v.Findings, PackFinding{
				Severity: "error", Path: rel,
				Reason: fmt.Sprintf("资源包总量 %d 字节超过 %d 上限", v.TotalBytes, l.TotalMaxBytes),
			})
			v.OK = false
			break
		}
	}

	v.HasMcmeta = hasMcmeta
	if !hasMcmeta {
		v.Findings = append(v.Findings, PackFinding{
			Severity: "error", Path: "$", Reason: "缺少根级 pack.mcmeta（不是合法资源包）",
		})
		v.OK = false
	} else {
		// 读取 pack.mcmeta 做 JSON 级校验。
		for _, f := range zr.File {
			if f.Name == "pack.mcmeta" {
				if f.UncompressedSize64 > uint64(l.McmetaBytes) {
					v.Findings = append(v.Findings, PackFinding{
						Severity: "error", Path: "pack.mcmeta",
						Reason: "pack.mcmeta 超过大小上限",
					})
					v.OK = false
					break
				}
				rc, err := f.Open()
				if err != nil {
					v.Findings = append(v.Findings, PackFinding{
						Severity: "error", Path: "pack.mcmeta",
						Reason: fmt.Sprintf("无法读取 pack.mcmeta：%v", err),
					})
					v.OK = false
					break
				}
				data := make([]byte, 0, int(f.UncompressedSize64)+1)
				buf := make([]byte, 8192)
				for {
					n, rerr := rc.Read(buf)
					if n > 0 {
						data = append(data, buf[:n]...)
					}
					if rerr != nil {
						break
					}
					if len(data) > l.McmetaBytes {
						break
					}
				}
				rc.Close()
				format, desc, mf := validateMcmeta(data, l)
				v.PackFormat = format
				v.PackDesc = desc
				for _, it := range mf {
					v.Findings = append(v.Findings, it)
					if it.Severity == "error" {
						v.OK = false
					}
				}
				break
			}
		}
	}

	// 汇总 OK：error 级发现已经逐条置位；无发现时默认真。
	if len(v.Findings) == 0 {
		v.OK = true
	} else {
		for _, it := range v.Findings {
			if it.Severity == "error" {
				v.OK = false
			}
		}
	}
	return v
}

// packVerdictSummary 生成一句话结论，供 UI / 日志使用（不输出敏感内容）。
func packVerdictSummary(v PackVerdict) string {
	if v.OK {
		return fmt.Sprintf("资源包可安全安装：%d 个条目 / %d 字节，pack_format=%d",
			v.EntryCount, v.TotalBytes, v.PackFormat)
	}
	return fmt.Sprintf("资源包存在 %d 个问题，拒绝安装", len(v.Findings))
}
