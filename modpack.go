package main

import (
	"archive/zip"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ===== Modrinth 整合包 API 结构体 =====

// ModpackSearchResult 整合包搜索结果（复用 Mod 搜索结构）
type ModpackSearchResult = ModSearchResult
type ModpackSearchResponse = ModSearchResponse

// ModrinthModpackManifest Modrinth 整合包 manifest.json
type ModrinthModpackManifest struct {
	FormatVersion int                  `json:"formatVersion"`
	Game          string               `json:"game"`
	VersionID     string               `json:"versionId"`
	Name          string               `json:"name"`
	Files         []ModrinthModpackFile `json:"files"`
	Dependencies  map[string]string    `json:"dependencies"`
}

// ModrinthModpackFile 整合包中的文件条目
type ModrinthModpackFile struct {
	Path      string            `json:"path"`
	Hashes    map[string]string `json:"hashes"`
	Downloads []string          `json:"downloads"`
	FileSize  int64             `json:"fileSize"`
}

// hasPathTraversalChars 检查路径是否包含路径遍历字符
func hasPathTraversalChars(path string) bool {
	return strings.Contains(path, "..") || strings.Contains(path, "\x00")
}

// safeJoin 安全地拼接路径，防止路径遍历
func safeJoin(baseDir, relPath string) (string, error) {
	if hasPathTraversalChars(relPath) {
		return "", fmt.Errorf("路径遍历检测: %s", relPath)
	}
	destPath := filepath.Join(baseDir, relPath)
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	absDest, err := filepath.Abs(destPath)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absDest, absBase+string(os.PathSeparator)) && absDest != absBase {
		return "", fmt.Errorf("路径越界: %s", relPath)
	}
	return destPath, nil
}

// sha1File 计算文件 SHA1（仅作 sha512 缺失时的回退）
func sha1File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyManifestHashes 优先用 SHA-512 校验（抗碰撞），缺失时才回退 SHA-1。
// 任一给定算法不匹配即删除文件并返回错误；两种摘要都未提供则跳过校验。
func verifyManifestHashes(path string, hashes map[string]string) error {
	want512 := strings.ToLower(strings.TrimSpace(hashes["sha512"]))
	want1 := strings.ToLower(strings.TrimSpace(hashes["sha1"]))

	if want512 != "" {
		got, err := sha512File(path)
		if err != nil {
			return err
		}
		if got != want512 {
			os.Remove(path)
			return fmt.Errorf("SHA-512 校验失败 (期望 %s, 实际 %s)", want512, got)
		}
		return nil
	}

	if want1 != "" {
		got, err := sha1File(path)
		if err != nil {
			return err
		}
		if got != want1 {
			os.Remove(path)
			return fmt.Errorf("SHA-1 校验失败 (期望 %s, 实际 %s)", want1, got)
		}
		return nil
	}
	return nil
}

// SearchModpacks 搜索 Modrinth 整合包
func (a *App) SearchModpacks(query string, gameVersion string, page int, pageSize int) (*ModpackSearchResponse, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page < 0 {
		page = 0
	}
	params := url.Values{}
	params.Set("query", query)
	params.Set("limit", fmt.Sprintf("%d", pageSize))
	params.Set("offset", fmt.Sprintf("%d", page*pageSize))
	params.Set("index", "relevance")

	var facets []string
	facets = append(facets, `["project_type:modpack"]`)
	if gameVersion != "" && isValidMCVersion(gameVersion) {
		facets = append(facets, fmt.Sprintf(`["versions:%s"]`, gameVersion))
	}
	if len(facets) > 0 {
		facetsJSON := fmt.Sprintf("[%s]", strings.Join(facets, ","))
		params.Set("facets", facetsJSON)
	}

	apiURL := fmt.Sprintf("%s/search?%s", modrinthBaseURL, params.Encode())
	resp, err := safeHTTPClient().Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("搜索整合包失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("搜索整合包失败: HTTP %d, %s", resp.StatusCode, string(body))
	}

	var result ModpackSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析搜索结果失败: %v", err)
	}

	if result.Hits == nil {
		result.Hits = []ModpackSearchResult{}
	}
	for i := range result.Hits {
		if result.Hits[i].Categories == nil {
			result.Hits[i].Categories = []string{}
		}
		if result.Hits[i].GameVersions == nil {
			result.Hits[i].GameVersions = []string{}
		}
		if result.Hits[i].Loaders == nil {
			result.Hits[i].Loaders = []string{}
		}
	}

	return &result, nil
}

// GetModpackVersions 获取整合包的版本列表
func (a *App) GetModpackVersions(projectID string) ([]ModVersion, error) {
	if !isValidModID(projectID) {
		return nil, fmt.Errorf("无效的项目 ID 格式")
	}
	apiURL := fmt.Sprintf("%s/project/%s/version", modrinthBaseURL, projectID)
	resp, err := safeHTTPClient().Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取整合包版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取整合包版本失败: HTTP %d", resp.StatusCode)
	}

	var versions []ModVersion
	if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
		return nil, fmt.Errorf("解析版本列表失败: %v", err)
	}

	if versions == nil {
		versions = []ModVersion{}
	}
	return versions, nil
}

// AddModpackToDownloadList 添加整合包到下载列表
func (a *App) AddModpackToDownloadList(versionID string, customName string) error {
	if !isValidModID(versionID) {
		return fmt.Errorf("无效的版本 ID 格式")
	}
	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)
	resp, err := safeHTTPClient().Get(apiURL)
	if err != nil {
		return fmt.Errorf("获取整合包版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取整合包版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
		return fmt.Errorf("解析版本详情失败: %v", err)
	}

	var primaryFile *ModFile
	for i := range version.Files {
		if version.Files[i].Primary {
			primaryFile = &version.Files[i]
			break
		}
	}
	if primaryFile == nil && len(version.Files) > 0 {
		primaryFile = &version.Files[0]
	}
	if primaryFile == nil {
		return fmt.Errorf("未找到整合包文件")
	}

	if !isHTTPSURL(primaryFile.URL) {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）")
	}

	displayName := filepath.Base(customName)
	if displayName == "" || displayName == "." {
		displayName = filepath.Base(primaryFile.Filename)
	}
	if displayName == "" || displayName == "." {
		displayName = filepath.Base(version.Name)
	}
	if displayName == "" || displayName == "." {
		displayName = "modpack"
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == displayName {
			return fmt.Errorf("下载列表中已存在: %s", displayName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         versionID,
		URL:        primaryFile.URL,
		CustomName: displayName,
		Type:       "modpack",
		ItemType:   "modpack",
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// installModpack 安装整合包
func (a *App) installModpack(item *DownloadItem) error {
	mcDir := a.GetMinecraftDir()

	tmpDir := filepath.Join(os.TempDir(), "qgl-modpack")
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return fmt.Errorf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mrpackPath := filepath.Join(tmpDir, "modpack.mrpack")
	a.emitProgress("downloading", item.CustomName, 0, 0)

	if !isHTTPSURL(item.URL) {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）")
	}

	resp, err := safeHTTPClient().Get(mirrorModURL(item.URL))
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		resp, err = safeHTTPClient().Get(item.URL)
		if err != nil {
			return fmt.Errorf("下载整合包失败: %v", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载整合包失败: HTTP %d", resp.StatusCode)
	}

	out, err := os.OpenFile(mrpackPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %v", err)
	}

	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				return werr
			}
			downloaded += int64(n)
			a.emitProgress("downloading", item.CustomName, downloaded, total)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			out.Close()
			return readErr
		}
	}
	out.Close()

	r, err := zip.OpenReader(mrpackPath)
	if err != nil {
		return fmt.Errorf("打开整合包失败: %v", err)
	}
	defer r.Close()

	var manifestEntry *zip.File
	for _, f := range r.File {
		if f.Name == "modrinth.index.json" {
			manifestEntry = f
			break
		}
	}
	if manifestEntry == nil {
		return fmt.Errorf("整合包中未找到 modrinth.index.json")
	}

	rc, err := manifestEntry.Open()
	if err != nil {
		return fmt.Errorf("读取 manifest 失败: %v", err)
	}
	manifestData, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return fmt.Errorf("读取 manifest 数据失败: %v", err)
	}

	var manifest ModrinthModpackManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("解析 manifest 失败: %v", err)
	}

	mcVersion := manifest.Dependencies["minecraft"]
	fabricVersion := manifest.Dependencies["fabric-loader"]
	forgeVersion := manifest.Dependencies["forge"]
	neoforgeVersion := manifest.Dependencies["neoforge"]
	quiltVersion := manifest.Dependencies["quilt-loader"]

	if mcVersion == "" {
		return fmt.Errorf("整合包未指定 Minecraft 版本")
	}

	a.emitProgress("downloading", "下载游戏 "+mcVersion, 0, 0)
	versionURL := ""
	mcManifest, err2 := a.GetVersionManifest()
	if err2 == nil {
		for _, v := range mcManifest {
			if v.ID == mcVersion {
				versionURL = v.URL
				break
			}
		}
	}
	if versionURL == "" {
		return fmt.Errorf("未找到 Minecraft %s 的下载地址", mcVersion)
	}
	if err := a.DownloadVersion(mcVersion, versionURL, mcVersion); err != nil {
		return fmt.Errorf("下载游戏版本失败: %v", err)
	}

	versionsDir := filepath.Join(mcDir, "versions")
	oldFolders := listVersionFolders(versionsDir)

	if fabricVersion != "" {
		a.emitProgress("downloading", "安装 Fabric "+fabricVersion, 0, 0)
		if err := a.InstallFabric(mcVersion, fabricVersion); err != nil {
			return fmt.Errorf("安装 Fabric 失败: %v", err)
		}
	} else if forgeVersion != "" {
		a.emitProgress("downloading", "安装 Forge "+forgeVersion, 0, 0)
		if err := a.InstallForge(mcVersion, forgeVersion); err != nil {
			return fmt.Errorf("安装 Forge 失败: %v", err)
		}
	} else if neoforgeVersion != "" {
		a.emitProgress("downloading", "安装 NeoForge "+neoforgeVersion, 0, 0)
		if err := a.InstallNeoForge(mcVersion, neoforgeVersion); err != nil {
			return fmt.Errorf("安装 NeoForge 失败: %v", err)
		}
	} else if quiltVersion != "" {
		return fmt.Errorf("Quilt 加载器暂不支持，请手动安装")
	}

	newFolders := listVersionFolders(versionsDir)
	versionDir := ""
	for _, f := range newFolders {
		if !containsStr(oldFolders, f) {
			versionDir = filepath.Join(versionsDir, f)
			break
		}
	}
	if versionDir == "" {
		versionDir = filepath.Join(versionsDir, mcVersion)
	}

	modsDir := filepath.Join(versionDir, "mods")
	if err := os.MkdirAll(modsDir, 0700); err != nil {
		return fmt.Errorf("创建 mods 目录失败: %v", err)
	}

	totalFiles := len(manifest.Files)
	for i, mf := range manifest.Files {
		destPath, err := safeJoin(versionDir, mf.Path)
		if err != nil {
			fmt.Printf("跳过不安全的文件路径(Zip Slip防护): %s, 错误: %v\n", mf.Path, err)
			continue
		}

		destDir := filepath.Dir(destPath)
		if err := os.MkdirAll(destDir, 0700); err != nil {
			continue
		}

		if _, err := os.Stat(destPath); err == nil {
			continue
		}

		fileName := filepath.Base(mf.Path)
		a.emitProgress("downloading", fmt.Sprintf("Mod %d/%d: %s", i+1, totalFiles, fileName), 0, mf.FileSize)

		tryOne := func(dlURL string) bool {
			if err := a.downloadFile(dlURL, destPath, false); err != nil {
				return false
			}
			if err := verifyManifestHashes(destPath, mf.Hashes); err != nil {
				fmt.Printf("文件完整性校验失败，尝试下一源: %s, %v\n", mf.Path, err)
				return false
			}
			return true
		}

		downloaded := false
		for _, dlURL := range mf.Downloads {
			if !isHTTPSURL(dlURL) {
				continue
			}
			if tryOne(mirrorModURL(dlURL)) {
				downloaded = true
				break
			}
			if tryOne(dlURL) {
				downloaded = true
				break
			}
		}
		if !downloaded {
			fmt.Printf("下载整合包文件失败(跳过): %s\n", mf.Path)
		}
	}

	a.emitProgress("downloading", "解压覆写文件", 0, 0)
	for _, f := range r.File {
		var relPath string
		if strings.HasPrefix(f.Name, "overrides/") {
			relPath = strings.TrimPrefix(f.Name, "overrides/")
		} else if strings.HasPrefix(f.Name, "client-overrides/") {
			relPath = strings.TrimPrefix(f.Name, "client-overrides/")
		} else {
			continue
		}

		if relPath == "" {
			continue
		}

		destPath, err := safeJoin(versionDir, relPath)
		if err != nil {
			fmt.Printf("跳过不安全的解压路径(Zip Slip防护): %s, 错误: %v\n", f.Name, err)
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0700)
			continue
		}

		os.MkdirAll(filepath.Dir(destPath), 0700)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}

	configDir := filepath.Join(versionDir, "QGL")
	if err := os.MkdirAll(configDir, 0700); err == nil {
		loaderType := ""
		if fabricVersion != "" {
			loaderType = "fabric"
		} else if forgeVersion != "" {
			loaderType = "forge"
		} else if neoforgeVersion != "" {
			loaderType = "neoforge"
		}
		config := map[string]string{
			"type":    "modpack",
			"name":    item.CustomName,
			"version": mcVersion,
			"loader":  loaderType,
		}
		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0600)
	}

	return nil
}

// listVersionFolders 列出 versions 目录下的所有子文件夹名
func listVersionFolders(versionsDir string) []string {
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return nil
	}
	var folders []string
	for _, e := range entries {
		if e.IsDir() {
			folders = append(folders, e.Name())
		}
	}
	return folders
}

// containsStr 检查字符串是否在切片中
func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
