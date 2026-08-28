package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// v2 安全加固：统一带超时的 HTTP 客户端，替换全文件裸 http.Get
var modpackHTTPClient = &http.Client{Timeout: 30 * time.Second}

// ===== Modrinth 整合包 API 结构体 =====

type ModpackSearchResult = ModSearchResult
type ModpackSearchResponse = ModSearchResponse

type ModrinthModpackManifest struct {
	FormatVersion int                  `json:"formatVersion"`
	Game          string               `json:"game"`
	VersionID     string               `json:"versionId"`
	Name          string               `json:"name"`
	Files         []ModrinthModpackFile `json:"files"`
	Dependencies  map[string]string    `json:"dependencies"`
}

type ModrinthModpackFile struct {
	Path      string            `json:"path"`
	Hashes    map[string]string `json:"hashes"`
	Downloads []string          `json:"downloads"`
	FileSize  int64             `json:"fileSize"`
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
	if gameVersion != "" {
		facets = append(facets, fmt.Sprintf(`["versions:%s"]`, gameVersion))
	}
	if len(facets) > 0 {
		facetsJSON := fmt.Sprintf("[%s]", strings.Join(facets, ","))
		params.Set("facets", facetsJSON)
	}
	apiURL := fmt.Sprintf("%s/search?%s", modrinthBaseURL, params.Encode())
	resp, err := modpackHTTPClient.Get(apiURL)
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
	apiURL := fmt.Sprintf("%s/project/%s/version", modrinthBaseURL, projectID)
	resp, err := modpackHTTPClient.Get(apiURL)
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
	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)
	resp, err := modpackHTTPClient.Get(apiURL)
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
	displayName := customName
	if displayName == "" {
		displayName = primaryFile.Filename
		if displayName == "" {
			displayName = version.Name
		}
	}
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	for _, item := range a.downloadList {
		if item.CustomName == displayName {
			return fmt.Errorf("下载列表中已存在: %s", displayName)
		}
	}
	a.downloadList = append(a.downloadList, DownloadItem{
		ID: versionID, URL: primaryFile.URL, CustomName: displayName,
		Type: "modpack", ItemType: "modpack", Status: "pending", Progress: 0,
	})
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// installModpack 安装整合包
func (a *App) installModpack(item *DownloadItem) error {
	mcDir := a.GetMinecraftDir()
	tmpDir := filepath.Join(os.TempDir(), "qgl-modpack")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	mrpackPath := filepath.Join(tmpDir, "modpack.mrpack")
	a.emitProgress("downloading", item.CustomName, 0, 0)
	resp, err := modpackHTTPClient.Get(mirrorModURL(item.URL))
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		resp, err = modpackHTTPClient.Get(item.URL)
		if err != nil {
			return fmt.Errorf("下载整合包失败: %v", err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载整合包失败: HTTP %d", resp.StatusCode)
	}
	out, err := os.Create(mrpackPath)
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
	if err := os.MkdirAll(modsDir, 0755); err != nil {
		return fmt.Errorf("创建 mods 目录失败: %v", err)
	}
	versionDirClean := filepath.Clean(versionDir) + string(os.PathSeparator)
	totalFiles := len(manifest.Files)
	for i, mf := range manifest.Files {
		// v2 安全加固：校验 mod 文件路径，防止 mf.Path 含 ../ 逃逸到版本目录之外
		destPath := filepath.Join(versionDir, mf.Path)
		if !strings.HasPrefix(filepath.Clean(destPath), versionDirClean) {
			fmt.Printf("路径遍历防护：跳过逃逸路径 %s\n", mf.Path)
			continue
		}
		destDir := filepath.Dir(destPath)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			continue
		}
		if _, err := os.Stat(destPath); err == nil {
			continue
		}
		fileName := filepath.Base(mf.Path)
		a.emitProgress("downloading", fmt.Sprintf("Mod %d/%d: %s", i+1, totalFiles, fileName), 0, mf.FileSize)
		downloaded := false
		for _, dlURL := range mf.Downloads {
			if err := a.downloadFile(mirrorModURL(dlURL), destPath, false); err == nil {
				downloaded = true
				break
			}
			if err := a.downloadFile(dlURL, destPath, false); err == nil {
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
		destPath := filepath.Join(versionDir, relPath)
		// v2 安全加固：zip slip 防护，防止 relPath 含 ../ 逃逸到版本目录之外
		if !strings.HasPrefix(filepath.Clean(destPath), versionDirClean) {
			fmt.Printf("zip slip 防护：跳过逃逸路径 %s\n", f.Name)
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(destPath), 0755)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	configDir := filepath.Join(versionDir, "QGL")
	if err := os.MkdirAll(configDir, 0755); err == nil {
		loaderType := ""
		if fabricVersion != "" {
			loaderType = "fabric"
		} else if forgeVersion != "" {
			loaderType = "forge"
		} else if neoforgeVersion != "" {
			loaderType = "neoforge"
		}
		config := map[string]string{
			"type": "modpack", "name": item.CustomName, "version": mcVersion, "loader": loaderType,
		}
		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0644)
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
