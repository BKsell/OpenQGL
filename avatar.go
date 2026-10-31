package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"image/png"
)

// ===== 用户头像（皮肤脸）获取 =====
// 参考 PCL（ModMinecraft.vb McSkinGetAddress / McSkinDownload + MySkin.Load）：
// 1. 通过 session server 的 UUID 接口获取 base64 纹理数据，解析出皮肤 URL
// 2. UUID -> 皮肤 URL 做持久缓存（对应 PCL 的 Cache\Skin\Index*.ini），避免频繁请求被 429 限流
// 3. 皮肤 URL hash -> 脸图文件缓存，URL 不变则直接复用
// 4. 从皮肤图裁剪 8x8 脸部 + 叠加帽子层（40,8），最近邻放大后返回 data URL
// 获取时机与 PCL 一致：前端在登录/选中用户后调用，失败或未设置皮肤则返回空（前端回退首字母）

// avatarIndex 头像地址缓存（QGL/Cache/Avatar/index.json）
type avatarIndex struct {
	Skins map[string]string `json:"skins"` // uuid -> 皮肤 URL
}

var avatarIndexMu sync.Mutex

func (a *App) avatarCacheDir() string {
	return filepath.Join(a.GetQGLDir(), "Cache", "Avatar")
}

func (a *App) loadAvatarIndex() *avatarIndex {
	avatarIndexMu.Lock()
	defer avatarIndexMu.Unlock()
	idx := &avatarIndex{Skins: map[string]string{}}
	data, err := os.ReadFile(filepath.Join(a.avatarCacheDir(), "index.json"))
	if err == nil {
		json.Unmarshal(data, idx)
	}
	if idx.Skins == nil {
		idx.Skins = map[string]string{}
	}
	return idx
}

func (a *App) saveAvatarIndex(idx *avatarIndex) {
	avatarIndexMu.Lock()
	defer avatarIndexMu.Unlock()
	os.MkdirAll(a.avatarCacheDir(), 0755)
	data, err := json.Marshal(idx)
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(a.avatarCacheDir(), "index.json"), data, 0644)
}

// GetUserAvatar 获取指定用户的头像（皮肤脸），返回 PNG data URL。
// 参数为用户标识 dir（UserInfo.Dir）；仅正版/外置用户有真实皮肤；
// 离线/访客返回空字符串，前端显示首字母。
func (a *App) GetUserAvatar(id string) (string, error) {
	userType := a.GetUserType(id)
	if userType != UserTypePremium && userType != UserTypeExternal {
		return "", nil
	}

	// 读取 UUID 与 session server 地址
	var uuid, sessionURL string
	if userType == UserTypePremium {
		auth, err := a.GetMSAuthData(id)
		if err != nil || auth.UUID == "" {
			return "", nil
		}
		uuid = auth.UUID
		sessionURL = "https://sessionserver.mojang.com/session/minecraft/profile/"
	} else {
		auth, err := a.GetExternalAuthData(id)
		if err != nil || auth.UUID == "" {
			return "", nil
		}
		uuid = auth.UUID
		// ServerURL 形如 https://littleskin.cn/api/yggdrasil，还原为站点根地址
		root := strings.TrimSuffix(strings.TrimSuffix(auth.ServerURL, "/"), "/api/yggdrasil")
		root = strings.TrimSuffix(root, "/authserver")
		sessionURL = root + "/sessionserver/session/minecraft/profile/"
	}
	if uuid == "" {
		return "", nil
	}

	// 1. 查皮肤地址缓存（uuid -> 皮肤 URL）
	idx := a.loadAvatarIndex()
	skinURL := idx.Skins[uuid]
	if skinURL == "" {
		url, err := fetchSkinURL(sessionURL + uuid)
		if err != nil {
			// 未设置自定义皮肤或网络失败：返回空（不缓存失败结果，下次重试）
			fmt.Printf("[Avatar] 获取皮肤地址失败（%s）: %v\n", id, err)
			return "", nil
		}
		if url == "" {
			return "", nil // 用户未设置自定义皮肤
		}
		skinURL = url
		idx.Skins[uuid] = skinURL
		a.saveAvatarIndex(idx)
	}

	// 2. 查脸图缓存（皮肤 URL hash -> png）；.v2 后缀用于 PCL 式合成算法升级后弃用旧缓存
	hash := fmt.Sprintf("%x", sha1.Sum([]byte(skinURL)))
	headPath := filepath.Join(a.avatarCacheDir(), hash+".v2.png")
	if data, err := os.ReadFile(headPath); err == nil && len(data) > 0 {
		return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data), nil
	}

	// 3. 下载皮肤并裁剪脸
	skinData, err := httpGetBytes(skinURL, 15*time.Second)
	if err != nil {
		fmt.Printf("[Avatar] 皮肤下载失败（%s）: %v\n", skinURL, err)
		return "", nil
	}
	facePNG, err := extractFacePNG(skinData)
	if err != nil {
		fmt.Printf("[Avatar] 裁剪头像失败（%s）: %v\n", id, err)
		return "", nil
	}

	// 4. 写缓存并返回
	os.MkdirAll(a.avatarCacheDir(), 0755)
	os.WriteFile(headPath, facePNG, 0644)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(facePNG), nil
}

// fetchSkinURL 从 session server 获取皮肤 URL，未设置自定义皮肤返回空串
func fetchSkinURL(profileURL string) (string, error) {
	body, err := httpGetBytes(profileURL, 8*time.Second)
	if err != nil {
		return "", err
	}
	var profile struct {
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		return "", fmt.Errorf("解析 profile 失败: %w", err)
	}
	var textureValue string
	for _, p := range profile.Properties {
		if p.Name == "textures" {
			textureValue = p.Value
			break
		}
	}
	if textureValue == "" {
		return "", nil // 未设置自定义皮肤（对应 PCL 的"皮肤返回值中不包含皮肤数据项"）
	}
	decoded, err := base64.StdEncoding.DecodeString(textureValue)
	if err != nil {
		return "", fmt.Errorf("解码 textures 失败: %w", err)
	}
	var textures struct {
		Textures struct {
			Skin struct {
				URL string `json:"url"`
			} `json:"skin"`
		} `json:"textures"`
	}
	if err := json.Unmarshal(decoded, &textures); err != nil {
		return "", fmt.Errorf("解析纹理数据失败: %w", err)
	}
	return textures.Textures.Skin.URL, nil
}

func httpGetBytes(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 皮肤最大 4MB，防止异常响应撑爆内存
}

// extractFacePNG 从 64x64（或 64x32）皮肤图中裁剪脸部并叠加帽子层，输出 64x64 PNG
func extractFacePNG(skinData []byte) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(skinData))
	if err != nil {
		return nil, fmt.Errorf("解码皮肤失败: %w", err)
	}
	bounds := img.Bounds()
	w := bounds.Dx()
	if w < 32 {
		return nil, fmt.Errorf("皮肤图片尺寸不足: %dx%d", w, bounds.Dy())
	}
	scale := w / 64
	if scale < 1 {
		scale = 1
	}
	fx, fy := bounds.Min.X, bounds.Min.Y
	// 按 PCL MySkin.Load 的档案头像合成逻辑：
	// 画布 56x56；脸层 (8,8) 8x8 放大到 48x48 居中（留 4px 边）；
	// 帽子/头发层 (40,8) 8x8 放大到 56x56 铺满叠加（头发包住脸并向外扩一圈）
	// 注意：64x32 旧皮肤也有帽子层（PCL 条件为 宽>=64 且 高>=32）
	const canvas = 56
	out := image.NewNRGBA(image.Rect(0, 0, canvas, canvas))

	// 采样函数：从皮肤图中取某 8x8 区域的像素
	sample := func(regionX, regionY, x, y int) (r, g, b, a uint32) {
		// 目标画布坐标 -> 区域内坐标（区域被放大到 56x56）
		rx := x * 8 / canvas
		ry := y * 8 / canvas
		return img.At(fx+regionX*scale+rx, fy+regionY*scale+ry).RGBA()
	}

	// 1. 脸层 48x48 居中（偏移 4px）：映射回 48x48 坐标再采样
	faceOffset, faceSize := 4, 48
	for y := 0; y < faceSize; y++ {
		for x := 0; x < faceSize; x++ {
			// 48x48 -> 8x8 采样
			rx := x * 8 / faceSize
			ry := y * 8 / faceSize
			out.Set(faceOffset+x, faceOffset+y, img.At(fx+8*scale+rx, fy+8*scale+ry))
		}
	}

	// 2. 帽子层 56x56 铺满，仅叠加不透明像素
	if bounds.Dy() >= 32*scale {
		for y := 0; y < canvas; y++ {
			for x := 0; x < canvas; x++ {
				_, _, _, a := sample(40, 8, x, y)
				if a>>8 > 0 {
					r, g, b, _ := sample(40, 8, x, y)
					out.SetNRGBA(x, y, color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)})
				}
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, out); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
