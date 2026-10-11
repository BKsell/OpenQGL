package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestPackZip 构造一个资源包 zip 到临时文件并返回路径。
// entries: name -> 内容；extraModes: name -> 覆盖的 mode（如符号链接）。
func buildTestPackZip(t *testing.T, entries map[string]string, extraModes map[string]os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.zip")
	fh, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(fh)
	for name, content := range entries {
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if mode, ok := extraModes[name]; ok {
			hdr.SetMode(mode)
		} else {
			hdr.SetMode(0644)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create header %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := fh.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}
	return path
}

func TestInspectResourcePackZip_OK(t *testing.T) {
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta":            `{"pack":{"pack_format":15,"description":"测试包"}}`,
		"assets/minecraft/lang/zh_cn.json": `{"key":"值"}`,
		"pack.png":               "png-bytes",
	}, nil)
	v := inspectResourcePackZip(path, defaultResourcePackLimits())
	if !v.OK {
		t.Fatalf("合法资源包被拒绝: %+v", v.Findings)
	}
	if !v.HasMcmeta || v.PackFormat != 15 || v.PackDesc != "测试包" {
		t.Fatalf("mcmeta 解析不符: %+v", v)
	}
	if v.EntryCount != 3 || v.TotalBytes <= 0 {
		t.Fatalf("统计不符: count=%d bytes=%d", v.EntryCount, v.TotalBytes)
	}
}

func TestInspectResourcePackZip_MissingMcmeta(t *testing.T) {
	path := buildTestPackZip(t, map[string]string{
		"assets/minecraft/textures/block/stone.png": "x",
	}, nil)
	v := inspectResourcePackZip(path, defaultResourcePackLimits())
	if v.OK {
		t.Fatal("缺少 pack.mcmeta 应拒绝")
	}
	if !hasPackFinding(v, "error", "pack.mcmeta") {
		t.Fatalf("应报缺少 pack.mcmeta: %+v", v.Findings)
	}
}

func TestInspectResourcePackZip_ZipSlip(t *testing.T) {
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta":   `{"pack":{"pack_format":15}}`,
		"../evil.txt":   "escape",
		"C:/evil2.txt":  "abs",
		`a\b\evil3.txt`: "backslash",
	}, nil)
	v := inspectResourcePackZip(path, defaultResourcePackLimits())
	if v.OK {
		t.Fatal("Zip Slip 条目应拒绝")
	}
	// 全部三条非法路径都应单独上报。
	names := map[string]bool{}
	for _, it := range v.Findings {
		names[it.Path] = true
	}
	if !names["../evil.txt"] || !names["C:/evil2.txt"] || !names[`a\b\evil3.txt`] {
		t.Fatalf("非法路径未全部上报: %+v", v.Findings)
	}
}

func TestInspectResourcePackZip_SymlinkEntry(t *testing.T) {
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta": `{"pack":{"pack_format":15}}`,
		"link":        "/etc/passwd",
	}, map[string]os.FileMode{"link": os.ModeSymlink | 0777})
	v := inspectResourcePackZip(path, defaultResourcePackLimits())
	if v.OK {
		t.Fatal("符号链接条目应拒绝")
	}
	if !hasPackFinding(v, "error", "link") {
		t.Fatalf("符号链接未上报: %+v", v.Findings)
	}
}

func TestInspectResourcePackZip_EntryTooLarge(t *testing.T) {
	l := defaultResourcePackLimits()
	l.EntryMaxBytes = 64
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta": `{"pack":{"pack_format":15}}`,
		"big.bin":     strings.Repeat("A", 128),
	}, nil)
	v := inspectResourcePackZip(path, l)
	if v.OK {
		t.Fatal("超限条目应拒绝")
	}
}

func TestInspectResourcePackZip_TotalTooLarge(t *testing.T) {
	l := defaultResourcePackLimits()
	l.TotalMaxBytes = 200
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta":        `{"pack":{"pack_format":15}}`,
		"assets/a.txt":       strings.Repeat("A", 120),
		"assets/b.txt":       strings.Repeat("B", 120),
	}, nil)
	v := inspectResourcePackZip(path, l)
	if v.OK {
		t.Fatal("总量超限应拒绝")
	}
}

func TestInspectResourcePackZip_McmetaTooLarge(t *testing.T) {
	l := defaultResourcePackLimits()
	l.McmetaBytes = 128
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta": `{"pack":{"pack_format":15,"description":"` + strings.Repeat("长", 200) + `"}}`,
	}, nil)
	v := inspectResourcePackZip(path, l)
	if v.OK {
		t.Fatal("超长 description 应拒绝")
	}
}

func TestInspectResourcePackZip_BadFormatWarnOnly(t *testing.T) {
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta": `{"pack":{"pack_format":9999,"description":"新格式"}}`,
	}, nil)
	v := inspectResourcePackZip(path, defaultResourcePackLimits())
	if !v.OK {
		t.Fatalf("超范围 pack_format 只是 warn，不应拒绝: %+v", v.Findings)
	}
	if !hasPackFinding(v, "warn", "pack.mcmeta") {
		t.Fatalf("应有 warn 级发现: %+v", v.Findings)
	}
}

func TestInspectResourcePackZip_BadJson(t *testing.T) {
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta": "{not json",
	}, nil)
	v := inspectResourcePackZip(path, defaultResourcePackLimits())
	if v.OK {
		t.Fatal("非法 JSON 应拒绝")
	}
}

func TestInspectResourcePackZip_NotAZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.zip")
	if err := os.WriteFile(path, []byte("plain text"), 0600); err != nil {
		t.Fatal(err)
	}
	v := inspectResourcePackZip(path, defaultResourcePackLimits())
	if v.OK {
		t.Fatal("非 zip 文件应拒绝")
	}
}

func TestClassifyZipEntryType(t *testing.T) {
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta": `{"pack":{"pack_format":15}}`,
		"dir/":        "",
	}, nil)
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var dirMode bool
	for _, f := range zr.File {
		if f.Name == "dir/" && classifyZipEntryType(f) == "dir" {
			dirMode = true
		}
	}
	if !dirMode {
		t.Fatal("目录条目识别失败")
	}
}

func TestValidateMcmeta_TranslateDescription(t *testing.T) {
	data := []byte(`{"pack":{"pack_format":15,"description":["a",{"text":"b"}]}}`)
	format, desc, findings := validateMcmeta(data, defaultResourcePackLimits())
	if format != 15 || len(findings) != 0 {
		t.Fatalf("translate 描述应通过: format=%d findings=%+v", format, findings)
	}
	if !strings.Contains(desc, "a") {
		t.Fatalf("描述未 JSON 化: %q", desc)
	}
}

func hasPackFinding(v PackVerdict, sev, path string) bool {
	for _, it := range v.Findings {
		if it.Severity == sev && it.Path == path {
			return true
		}
	}
	return false
}

func TestPackVerdictSummary(t *testing.T) {
	path := buildTestPackZip(t, map[string]string{
		"pack.mcmeta": `{"pack":{"pack_format":15}}`,
		"a.txt":       "x",
	}, nil)
	v := inspectResourcePackZip(path, defaultResourcePackLimits())
	s := packVerdictSummary(v)
	if !strings.Contains(s, "可安全安装") {
		t.Fatalf("summary 不符: %s", s)
	}
	bad := inspectResourcePackZip(path, ResourcePackLimits{MaxEntries: 1})
	if strings.Contains(packVerdictSummary(bad), "可安全安装") {
		t.Fatal("拒绝态 summary 不应说可安装")
	}
}
