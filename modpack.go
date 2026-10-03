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
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// 解压覆写文件时的大小上限，防止 zip bomb（高压缩比小文件膨胀占满磁盘）。
const (
	maxOverridesEntryBytes int64 = 8 << 30  // 单个文件最多 8 GiB（正常整合包条目远小于此，只有解压炸弹才会触发）
	maxOverridesTotalBytes int64 = 256 << 30 // 全部覆写文件合计最多 256 GiB（只在明显炸磁盘时中止）
	maxMrpackDownloadBytes  int64 = 8 << 30  // 整合包本体最多 8 GiB，与单文件上限一致
	maxMrpackManifestBytes  int64 = 16 << 20 // modrinth.index.json 最多 16 MiB（清单只是文件列表，正常远小于此）
	maxOverridesEntries     = 100000        // 覆写条目数上限，防海量空文件耗尽 inode / 拖慢解压
)

// unsafeEntryMode 拒绝在覆写区落地的特殊文件类型：符号链接 / 设备 / 管道 / 套接字。
// zip 里这类条目本不该出现在整合包，放行符号链接还可能被利用做链接逃逸或诱导覆盖。
const unsafeEntryMode = os.ModeSymlink | os.ModeDevice | os.ModeNamedPipe | os.ModeSocket

// ===== Modrinth 整合包 API 结构体 =====

type ModpackSearchResult = ModSearchResult
type ModpackSearchResponse = ModSearchResponse

type ModrinthModpackManifest struct {
	FormatVersion int                   `json:"formatVersion"`
	Game          string                `json:"game"`
	VersionID     string                `json:"versionId"`
	Name          string                `json:"name"`
	Files         []ModrinthModpackFile `json:"files"`
	Dependencies  map[string]string     `json:"dependencies"`
}

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

// ===== UMFS 本地完整性缓存 =====
// 首次下载用 Modrinth 给的 sha512 验完后，把文件的 UMFS-256 指纹缓存到本地；
// 以后再遇到同一文件（用 Modrinth 的 sha512/sha1 当 key）就优先比对 UMFS。
// 优先级：缓存 UMFS → manifest sha512 → manifest sha1。

type umfsCache struct {
	mu   sync.Mutex
	path string
	data map[string]string
}

var globalUMFSCache *umfsCache
var umfsCacheOnce sync.Once

func getUMFSCache(cachePath string) *umfsCache {
	umfsCacheOnce.Do(func() {
		globalUMFSCache = &umfsCache{path: cachePath, data: map[string]string{}}
		if raw, err := os.ReadFile(cachePath); err == nil {
			_ = json.Unmarshal(raw, &globalUMFSCache.data)
		}
	})
	return globalUMFSCache
}

func (c *umfsCache) keyFor(hashes map[string]string) string {
	if v := strings.ToLower(strings.TrimSpace(hashes["sha512"])); v != "" {
		return "sha512:" + v
	}
	if v := strings.ToLower(strings.TrimSpace(hashes["sha1"])); v != "" {
		return "sha1:" + v
	}
	return ""
}

func (c *umfsCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[key]
	return v, ok
}

func (c *umfsCache) set(key, umfsHex string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = umfsHex
	raw, _ := json.MarshalIndent(c.data, "", "  ")
	os.MkdirAll(filepath.Dir(c.path), 0700)
	os.WriteFile(c.path, raw, 0600)
}

// verifyDownloadedFile 按优先级校验：缓存 UMFS → sha512 → sha1。
// 任一可信算法通过后会把 UMFS 指纹写回缓存。
func verifyDownloadedFile(path string, hashes map[string]string, cache *umfsCache) error {
	want512 := strings.ToLower(strings.TrimSpace(hashes["sha512"]))
	want1 := strings.ToLower(strings.TrimSpace(hashes["sha1"]))

	pinUMFS := func() {
		if cache == nil {
			return
		}
		key := cache.keyFor(hashes)
		if key == "" {
			return
		}
		if u, err := umfsFile(path); err == nil {
			cache.set(key, u)
		}
	}

	// 1) 缓存命中：优先 UMFS
	if cache != nil {
		if key := cache.keyFor(hashes); key != "" {
			if want, ok := cache.get(key); ok {
				got, err := umfsFile(path)
				if err != nil {
					return err
				}
				if got == want {
					return nil
				}
				// UMFS 不匹配：可能是文件被换过，继续走下面的官方摘要校验
				os.Remove(path)
				return fmt.Errorf("UMFS 缓存校验失败 (期望 %s, 实际 %s)", want, got)
			}
		}
	}

	// 2) sha512
	if want512 != "" {
		got, err := sha512File(path)
		if err != nil {
			return err
		}
		if got != want512 {
			os.Remove(path)
			return fmt.Errorf("SHA-512 校验失败 (期望 %s, 实际 %s)", want512, got)
		}
		pinUMFS()
		return nil
	}

	// 3) sha1 回退
	if want1 != "" {
		got, err := sha1File(path)
		if err != nil {
			return err
		}
		if got != want1 {
			os.Remove(path)
			return fmt.Errorf("SHA-1 校验失败 (期望 %s, 实际 %s)", want1, got)
		}
		pinUMFS()
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("搜索整合包失败: HTTP %d, %s", resp.StatusCode, string(body))
	}

	var result ModpackSearchResponse
	if err := readAPIJSON(resp, &result); err != nil {
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

// GetModpackVersions 获取整合包版本列表
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
	if err := readAPIJSON(resp, &versions); err != nil {
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
	if err := readAPIJSON(resp, &version); err != nil {
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

	// 展示名优先用前端传入的 customName，其次服务端文件名 / 版本名；无论哪个来源都可能
	// 带控制字符或保留设备名，统一走严格版本名内核，全部不可信时回退固定安全名。
	displayName := ""
	for _, cand := range []string{customName, primaryFile.Filename, version.Name} {
		base := filepath.Base(strings.TrimSpace(cand))
		if clean, why := SafeVersionComponent(base); why == nameRejectNone {
			displayName = clean
			break
		}
	}
	if displayName == "" {
		displayName = "modpack"
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	pending := DownloadItem{
		ID:         versionID,
		URL:        primaryFile.URL,
		CustomName: displayName,
		Type:       "modpack",
		ItemType:   "modpack",
		Status:     "pending",
		Progress:   0,
	}
	if why := auditDownloadItemForEnqueue(a.downloadList, pending); why != dqRejectNone {
		return fmt.Errorf("%s", describeQueueReject(why))
	}

	a.downloadList = append(a.downloadList, pending)

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// installModpack 安装整合包
func (a *App) installModpack(item *DownloadItem) error {
	mcDir := a.GetMinecraftDir()

	// 用每次安装唯一的临时目录（权限 0700），而不是固定的 qgl-modpack/modpack.mrpack。
	// 固定路径可被本地其他进程提前放成符号链接，随后 O_CREATE|O_TRUNC 会跟随链接
	// 截断任意可写文件；MkdirTemp 生成不可预测的目录名，杜绝该预置链接攻击面。
	tmpDir, err := os.MkdirTemp("", "qgl-modpack-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %v", err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("设置临时目录权限失败: %v", err)
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

	// O_EXCL 保证文件由我们新建：即便唯一临时目录内被抢先放入同名符号链接也直接报错，
	// 不会跟随链接截断其它文件。
	out, err := os.OpenFile(mrpackPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %v", err)
	}

	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if downloaded+int64(n) > maxMrpackDownloadBytes {
				out.Close()
				os.Remove(mrpackPath)
				return fmt.Errorf("整合包体积超过 %d 字节上限，拒绝写入(防炸磁盘)", maxMrpackDownloadBytes)
			}
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
	// mrpack 来自第三方下载源，manifest 条目同样可被塞成解压炸弹：
	// 先用 zip 元数据预检，再用 LimitReader 多读 1 字节判定真实超限。
	if manifestEntry.UncompressedSize64 > uint64(maxMrpackManifestBytes) {
		rc.Close()
		return fmt.Errorf("manifest 体积超过 %d 字节上限，拒绝读取(解压炸弹防护)", maxMrpackManifestBytes)
	}
	manifestData, err := io.ReadAll(io.LimitReader(rc, maxMrpackManifestBytes+1))
	rc.Close()
	if err != nil {
		return fmt.Errorf("读取 manifest 数据失败: %v", err)
	}
	if int64(len(manifestData)) > maxMrpackManifestBytes {
		return fmt.Errorf("manifest 体积超过 %d 字节上限，拒绝解析(解压炸弹防护)", maxMrpackManifestBytes)
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

	// dependencies.* 全部来自不可信的第三方 .mrpack：mcVersion 最终会进
	// versions/<mcVersion>，fabric/forge/neoforge 版本会拼进出向元数据 URL 与版本
	// 目录名。这里集中做严格名单段校验，任何控制字符/分隔符/保留设备名/超长都直接
	// 终止安装，避免畸形清单把文件导向 versions 目录外或污染对 Modrinth/Forge 的请求。
	if clean, why := SafeVersionComponent(mcVersion); why != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"modpack", "整合包 minecraft 版本标识非法: "+describeNameReject(why))
		return fmt.Errorf("整合包声明的 Minecraft 版本非法: %s", describeNameReject(why))
	} else {
		mcVersion = clean
	}
	checkLoaderDep := func(label, value string) (string, error) {
		if value == "" {
			return "", nil
		}
		clean, why := SafeLoaderComponent(value)
		if why != nameRejectNone {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
				"modpack", "整合包 "+label+" 版本标识非法: "+describeNameReject(why))
			return "", fmt.Errorf("整合包声明的 %s 版本非法: %s", label, describeNameReject(why))
		}
		return clean, nil
	}
	if v, err := checkLoaderDep("fabric-loader", fabricVersion); err != nil {
		return err
	} else {
		fabricVersion = v
	}
	if v, err := checkLoaderDep("forge", forgeVersion); err != nil {
		return err
	} else {
		forgeVersion = v
	}
	if v, err := checkLoaderDep("neoforge", neoforgeVersion); err != nil {
		return err
	} else {
		neoforgeVersion = v
	}
	if quiltVersion != "" {
		if _, why := SafeLoaderComponent(quiltVersion); why != nameRejectNone {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
				"modpack", "整合包 quilt-loader 版本标识非法: "+describeNameReject(why))
			return fmt.Errorf("整合包声明的 quilt-loader 版本非法: %s", describeNameReject(why))
		}
	}

	// 初始化 UMFS 本地缓存
	cachePath := filepath.Join(mcDir, "QGL", "umfs_cache.json")
	cache := getUMFSCache(cachePath)

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
			if err := verifyDownloadedFile(destPath, mf.Hashes, cache); err != nil {
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

	// 覆写文件解压统一走 zipextract 安全内核：
	// Zip Slip、符号链接 / 设备等特殊条目、重复落盘路径在预检阶段整体拒绝；
	// 条目数 / 单文件 8 GiB / 总量 256 GiB 上限先按声明值预检，落盘再用
	// LimitReader 复核；每个文件先写同目录临时文件，校验通过后原子替换。
	lim := zipExtractLimits{
		EntryMax:   maxOverridesEntryBytes,
		TotalMax:   maxOverridesTotalBytes,
		MaxEntries: maxOverridesEntries,
	}
	extractedBytes, extractedFiles, err := extractZipPrefixes(
		r.File, versionDir,
		[]string{"overrides/", "client-overrides/"},
		lim,
		func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
	)
	if err != nil {
		return fmt.Errorf("解压覆写文件失败: %w", err)
	}
	fmt.Printf("覆写文件解压完成: %d 个文件，共 %d 字节\n", extractedFiles, extractedBytes)

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

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
