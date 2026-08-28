package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

const (
	oauthClientID = ""//修改为你的client id
	oauthScope    = "XboxLive.signin offline_access"

	// Microsoft OAuth endpoints
	deviceCodeURL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
	tokenURL      = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"

	// Xbox Live endpoints
	xblAuthURL  = "https://user.auth.xboxlive.com/user/authenticate"
	xstsAuthURL = "https://xsts.auth.xboxlive.com/xsts/authorize"

	// Minecraft services endpoints
	mcLoginURL       = "https://api.minecraftservices.com/authentication/login_with_xbox"
	mcEntitlementURL = "https://api.minecraftservices.com/entitlements/mcstore"
	mcProfileURL     = "https://api.minecraftservices.com/minecraft/profile"
)

// MSAuthData 微软认证数据（存储在用户目录的 ms_auth.json）
type MSAuthData struct {
	AccessToken   string `json:"accessToken"`
	RefreshToken  string `json:"refreshToken"`
	MCAccessToken string `json:"mcAccessToken"`
	UUID          string `json:"uuid"`
	Username      string `json:"username"`
	ExpiresAt     int64  `json:"expiresAt"`
	MCExpiresAt   int64  `json:"mcExpiresAt"`
}

// MSAuthDataEncrypted 加密存储的认证数据格式
type MSAuthDataEncrypted struct {
	Username string `json:"username"` // 用户名不加密
	Data     string `json:"data"`     // 其余字段加密后的 base64 字符串
}

// ExternalAuthDataEncrypted 外置认证数据加密存储格式
type ExternalAuthDataEncrypted struct {
	ServerName string `json:"serverName"` // 服务器名称不加密
	Data       string `json:"data"`       // 其余字段加密后的 base64 字符串
}

// getEncryptionKey 根据用户名+OQL生成 32 字节 AES 密钥
func getEncryptionKey(username string) []byte {
	raw := username + "OQL"
	// 使用 SHA-256 风格的简单派生：取前 32 字节
	key := make([]byte, 32)
	for i := 0; i < len(raw); i++ {
		key[i%32] ^= raw[i]
	}
	// 多轮混合确保均匀分布
	for round := 0; round < 64; round++ {
		for i := 0; i < 32; i++ {
			key[i] = key[i] ^ key[(i+1)%32] ^ byte(round)
		}
	}
	return key
}

// aesGCMEncrypt 使用 AES-GCM 加密数据，返回 base64 编码的密文
func aesGCMEncrypt(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// aesGCMDecrypt 使用 AES-GCM 解密 base64 编码的密文
func aesGCMDecrypt(encoded string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("密文太短")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// DeviceCodeResponse 设备代码响应
type DeviceCodeResponse struct {
	UserCode         string `json:"user_code"`
	DeviceCode       string `json:"device_code"`
	VerificationURL  string `json:"verification_uri"`
	ExpiresIn        int    `json:"expires_in"`
	Interval         int    `json:"interval"`
	Message          string `json:"message"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// TokenResponse 令牌响应
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	ExpiresIn       int    `json:"expires_in"`
	TokenType       string `json:"token_type"`
	Scope           string `json:"scope"`
	Error           string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// XBLAuthResponse Xbox Live 认证响应
type XBLAuthResponse struct {
	IssueInstant  string `json:"IssueInstant"`
	NotAfter      string `json:"NotAfter"`
	Token         string `json:"Token"`
	DisplayClaims struct {
		XUI []struct {
			UHS string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
}

// XSTSAuthResponse XSTS 认证响应
type XSTSAuthResponse struct {
	IssueInstant  string `json:"IssueInstant"`
	NotAfter      string `json:"NotAfter"`
	Token         string `json:"Token"`
	DisplayClaims struct {
		XUI []struct {
			UHS string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
	ErrorCode int    `json:"XErr"`
	Message   string `json:"Message"`
}

// MCLoginResponse Minecraft 登录响应
type MCLoginResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Username    string `json:"username"`
	// 错误字段
	Error            string `json:"error"`
	ErrorMessage     string `json:"errorMessage"`
	DeveloperMessage string `json:"developerMessage"`
}

// MCProfileResponse Minecraft 玩家档案响应
type MCProfileResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MCEntitlementResponse Minecraft 所有权验证响应
type MCEntitlementResponse struct {
	Items []struct {
		Name string `json:"name"`
	} `json:"items"`
}

// StartMicrosoftLogin 开始微软登录流程（Device Code Flow）
func (a *App) StartMicrosoftLogin() (string, error) {
	// Step 1: 请求设备代码
	data := url.Values{
		"client_id": {oauthClientID},
		"scope":     {oauthScope},
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(deviceCodeURL, data)
	if err != nil {
		return "", fmt.Errorf("请求设备代码失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取设备代码响应失败: %v", err)
	}

	var dcResp DeviceCodeResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		return "", fmt.Errorf("解析设备代码响应失败: %v (原始: %s)", err, string(body))
	}

	if dcResp.Error != "" {
		return "", fmt.Errorf("设备代码错误: %s - %s", dcResp.Error, dcResp.ErrorDescription)
	}

	// 自动打开验证链接
	openCmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", dcResp.VerificationURL)
	openCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	openCmd.Start()

	// 自动复制用户代码到剪贴板
	runtime.ClipboardSetText(a.ctx, dcResp.UserCode)

	// 在后台轮询令牌
	go a.pollMicrosoftToken(dcResp)

	// 返回用户需要访问的URL和代码
	result := fmt.Sprintf("%s|%s", dcResp.VerificationURL, dcResp.UserCode)
	return result, nil
}

// pollMicrosoftToken 轮询微软令牌
func (a *App) pollMicrosoftToken(dc DeviceCodeResponse) {
	interval := 5
	if dc.Interval > 0 {
		interval = dc.Interval
	}

	for {
		time.Sleep(time.Duration(interval) * time.Second)

		data := url.Values{
			"client_id":   {oauthClientID},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dc.DeviceCode},
		}

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.PostForm(tokenURL, data)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var tokenResp TokenResponse
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			continue
		}

		if tokenResp.Error != "" {
			if tokenResp.Error == "authorization_pending" {
				continue
			}
			if tokenResp.Error == "slow_down" {
				interval += 5
				continue
			}
			if tokenResp.Error == "expired_token" {
				runtime.EventsEmit(a.ctx, "msLoginError", "登录已过期，请重新尝试")
				return
			}
			runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("登录失败: %s", tokenResp.ErrorDescription))
			return
		}

		// 获取到 Microsoft Access Token，继续后续步骤
		a.completeMicrosoftLogin(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
		return
	}
}

// completeMicrosoftLogin 完成微软登录的后续步骤（Xbox → Minecraft）
func (a *App) completeMicrosoftLogin(msAccessToken string, msRefreshToken string, msExpiresIn int) {
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证 Xbox Live...")

	// Step 2: OAuth Token → XBL Token
	xblToken, _, err := a.authXBL(msAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("Xbox Live 验证失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取 XSTS 令牌...")

	// Step 3: XBL Token → XSTS Token + UHS
	xstsToken, xstsUHS, err := a.authXSTS(xblToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("XSTS 验证失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在登录 Minecraft...")

	// Step 4: XSTS Token → Minecraft Access Token
	// 注意：使用 XSTS 返回的 UHS，而不是 XBL 的 UHS
	mcAccessToken, mcExpiresIn, err := a.authMinecraft(xstsToken, xstsUHS)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("Minecraft 登录失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证游戏所有权...")

	// Step 5: 验证是否持有 Minecraft
	hasGame, err := a.checkMCEntitlement(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("验证游戏所有权失败: %v", err))
		return
	}
	if !hasGame {
		runtime.EventsEmit(a.ctx, "msLoginError", "该微软账号未购买 Minecraft Java 版，或 Xbox Game Pass 已过期")
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取玩家档案...")

	// Step 6: 获取玩家档案
	profile, err := a.getMCProfile(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("获取玩家档案失败: %v", err))
		return
	}

	// 保存认证数据
	authData := MSAuthData{
		AccessToken:   msAccessToken,
		RefreshToken:  msRefreshToken,
		MCAccessToken: mcAccessToken,
		UUID:          profile.ID,
		Username:      profile.Name,
		ExpiresAt:     time.Now().Add(time.Duration(msExpiresIn) * time.Second).Unix(),
		MCExpiresAt:   time.Now().Add(time.Duration(mcExpiresIn) * time.Second).Unix(),
	}

	// 创建正版用户
	if err := a.CreatePremiumUser(profile.Name, authData); err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("创建用户失败: %v", err))
		return
	}

	// 设置为当前用户
	if err := a.SetCurrentUser(profile.Name); err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("设置当前用户失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginSuccess", profile.Name)
}

// authXBL Step 2: 用 OAuth Token 换取 XBL Token
func (a *App) authXBL(accessToken string) (string, string, error) {
	payload := map[string]interface{}{
		"Properties": map[string]string{
			"AuthMethod": "RPS",
			"SiteName":   "user.auth.xboxlive.com",
			"RpsTicket":  "d=" + accessToken,
		},
		"RelyingParty": "http://auth.xboxlive.com",
		"TokenType":    "JWT",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(xblAuthURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("XBL 请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("XBL 请求失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var xblResp XBLAuthResponse
	if err := json.Unmarshal(respBody, &xblResp); err != nil {
		return "", "", fmt.Errorf("XBL 响应解析失败: %s", string(respBody))
	}

	if xblResp.Token == "" {
		return "", "", fmt.Errorf("XBL 响应中缺少 Token")
	}
	if len(xblResp.DisplayClaims.XUI) == 0 {
		return "", "", fmt.Errorf("XBL 响应中缺少 UHS")
	}

	return xblResp.Token, xblResp.DisplayClaims.XUI[0].UHS, nil
}

// authXSTS Step 3: 用 XBL Token 换取 XSTS Token + UHS
func (a *App) authXSTS(xblToken string) (string, string, error) {
	payload := map[string]interface{}{
		"Properties": map[string]interface{}{
			"SandboxId":  "RETAIL",
			"UserTokens": []string{xblToken},
		},
		"RelyingParty": "rp://api.minecraftservices.com/",
		"TokenType":    "JWT",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(xstsAuthURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("XSTS 请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	// 先检查是否有 XErr 错误码
	var xstsErrResp struct {
		XErr   int    `json:"XErr"`
		Message string `json:"Message"`
	}
	json.Unmarshal(respBody, &xstsErrResp)
	if xstsErrResp.XErr != 0 {
		switch xstsErrResp.XErr {
		case 2148916233:
			return "", "", fmt.Errorf("该微软账号未关联 Xbox 账号")
		case 2148916235:
			return "", "", fmt.Errorf("Xbox Live 在您所在地区不可用")
		case 2148916236:
			return "", "", fmt.Errorf("该 Xbox 账号需要成人确认才能登录")
		case 2148916237:
			return "", "", fmt.Errorf("该 Xbox 账号已被封禁")
		case 2148916238:
			return "", "", fmt.Errorf("该账号是未成年人账号，无法完成登录")
		default:
			return "", "", fmt.Errorf("XSTS 错误 %d: %s", xstsErrResp.XErr, xstsErrResp.Message)
		}
	}

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("XSTS 请求失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var xstsResp XSTSAuthResponse
	if err := json.Unmarshal(respBody, &xstsResp); err != nil {
		return "", "", fmt.Errorf("XSTS 响应解析失败: %s", string(respBody))
	}

	if xstsResp.Token == "" {
		return "", "", fmt.Errorf("XSTS 响应中缺少 Token")
	}
	if len(xstsResp.DisplayClaims.XUI) == 0 {
		return "", "", fmt.Errorf("XSTS 响应中缺少 UHS")
	}

	return xstsResp.Token, xstsResp.DisplayClaims.XUI[0].UHS, nil
}

// authMinecraft Step 4: 用 XSTS Token 换取 Minecraft Access Token
func (a *App) authMinecraft(xstsToken string, uhs string) (string, int, error) {
	identityToken := fmt.Sprintf("XBL3.0 x=%s;%s", uhs, xstsToken)
	payload := map[string]string{
		"identityToken": identityToken,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(mcLoginURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", 0, fmt.Errorf("Minecraft 登录请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	// 先检查是否有错误响应
	var mcErrResp MCLoginResponse
	json.Unmarshal(respBody, &mcErrResp)
	if mcErrResp.Error != "" {
		errMsg := mcErrResp.ErrorMessage
		if errMsg == "" {
			errMsg = mcErrResp.DeveloperMessage
		}
		if errMsg == "" {
			errMsg = mcErrResp.Error
		}
		return "", 0, fmt.Errorf("Minecraft 登录失败: %s (HTTP %d)", errMsg, resp.StatusCode)
	}

	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("Minecraft 登录失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var mcResp MCLoginResponse
	if err := json.Unmarshal(respBody, &mcResp); err != nil {
		return "", 0, fmt.Errorf("Minecraft 登录响应解析失败: %s", string(respBody))
	}

	if mcResp.AccessToken == "" {
		return "", 0, fmt.Errorf("未获取到 Minecraft Access Token (响应: %s)", string(respBody))
	}

	expiresIn := mcResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 86400 // 默认24小时
	}

	return mcResp.AccessToken, expiresIn, nil
}

// checkMCEntitlement Step 5: 验证是否持有 Minecraft
func (a *App) checkMCEntitlement(mcAccessToken string) (bool, error) {
	req, err := http.NewRequest("GET", mcEntitlementURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var entResp MCEntitlementResponse
	if err := json.Unmarshal(body, &entResp); err != nil {
		return false, err
	}

	return len(entResp.Items) > 0, nil
}

// getMCProfile Step 6: 获取玩家档案
func (a *App) getMCProfile(mcAccessToken string) (*MCProfileResponse, error) {
	req, err := http.NewRequest("GET", mcProfileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("获取玩家档案失败 (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var profile MCProfileResponse
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("解析玩家档案失败: %s", string(body))
	}

	if profile.ID == "" || profile.Name == "" {
		return nil, fmt.Errorf("玩家档案为空: %s", string(body))
	}

	return &profile, nil
}

// RefreshMicrosoftToken 刷新微软令牌
func (a *App) RefreshMicrosoftToken(username string) error {
	authData, err := a.GetMSAuthData(username)
	if err != nil {
		return fmt.Errorf("读取认证数据失败: %v", err)
	}

	if authData.RefreshToken == "" {
		return fmt.Errorf("无刷新令牌，请重新登录")
	}

	// 检查是否需要刷新
	if time.Now().Unix() < authData.MCExpiresAt-60 {
		return nil
	}

	// 用 refresh_token 获取新的 access_token
	data := url.Values{
		"client_id":     {oauthClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {authData.RefreshToken},
		"scope":         {oauthScope},
	}

	client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.PostForm(tokenURL, data)
	if err != nil {
		return fmt.Errorf("刷新令牌请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return err
	}

	if tokenResp.Error != "" {
		return fmt.Errorf("刷新令牌失败: %s", tokenResp.ErrorDescription)
	}

	// 重新走 Xbox → Minecraft 流程
	xblToken, _, err := a.authXBL(tokenResp.AccessToken)
	if err != nil {
		return err
	}

	xstsToken, xstsUHS, err := a.authXSTS(xblToken)
	if err != nil {
		return err
	}

	mcAccessToken, mcExpiresIn, err := a.authMinecraft(xstsToken, xstsUHS)
	if err != nil {
		return err
	}

	// 更新存储
	authData.AccessToken = tokenResp.AccessToken
	authData.RefreshToken = tokenResp.RefreshToken
	authData.MCAccessToken = mcAccessToken
	authData.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix()
	authData.MCExpiresAt = time.Now().Add(time.Duration(mcExpiresIn) * time.Second).Unix()

	return a.SaveMSAuthData(username, authData)
}

// GetMSAuthData 获取微软认证数据（自动处理加密/明文兼容）
func (a *App) GetMSAuthData(username string) (*MSAuthData, error) {
	authPath := filepath.Join(a.GetUsersDir(), username, "ms_auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		return nil, err
	}

	// 先尝试按加密格式解析
	var encData MSAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		// 加密格式：解密 Data 字段
		key := getEncryptionKey(username)
		decrypted, err := aesGCMDecrypt(encData.Data, key)
		if err != nil {
			return nil, fmt.Errorf("解密认证数据失败: %w", err)
		}
		var authData MSAuthData
		if err := json.Unmarshal(decrypted, &authData); err != nil {
			return nil, fmt.Errorf("解析解密后的认证数据失败: %w", err)
		}
		authData.Username = username // 确保用户名正确
		return &authData, nil
	}

	// 兼容旧版明文格式
	var authData MSAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, err
	}
	return &authData, nil
}

// SaveMSAuthData 保存微软认证数据（加密存储，username 以外的字段全部加密）
func (a *App) SaveMSAuthData(username string, authData *MSAuthData) error {
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return err
	}

	// 构建需要加密的数据（除 username 以外的所有字段）
	encryptPayload := map[string]interface{}{
		"accessToken":   authData.AccessToken,
		"refreshToken":  authData.RefreshToken,
		"mcAccessToken": authData.MCAccessToken,
		"uuid":          authData.UUID,
		"expiresAt":     authData.ExpiresAt,
		"mcExpiresAt":   authData.MCExpiresAt,
	}
	payloadBytes, err := json.Marshal(encryptPayload)
	if err != nil {
		return err
	}

	// 加密
	key := getEncryptionKey(username)
	encrypted, err := aesGCMEncrypt(payloadBytes, key)
	if err != nil {
		return fmt.Errorf("加密认证数据失败: %w", err)
	}

	// 构建加密后的存储格式
	encData := MSAuthDataEncrypted{
		Username: username,
		Data:     encrypted,
	}

	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(userDir, "ms_auth.json"), data, 0600)
}

// ===== Yggdrasil 外置登录 =====

// YggdrasilAuthResponse Yggdrasil 认证响应
type YggdrasilAuthResponse struct {
	AccessToken      string `json:"accessToken"`
	ClientToken      string `json:"clientToken"`
	AvailableProfiles []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"availableProfiles"`
	SelectedProfile *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"selectedProfile"`
	Error            string `json:"error"`
	ErrorMessage     string `json:"errorMessage"`
	Cause            string `json:"cause"`
}

// YggdrasilServerMeta Yggdrasil 服务器元信息
type YggdrasilServerMeta struct {
	ServerName string `json:"serverName"`
}

// YggdrasilServerLinks Yggdrasil 服务器链接
type YggdrasilServerLinks struct {
	Homepage string `json:"homepage"`
	Register string `json:"register"`
}

// YggdrasilServerInfo Yggdrasil 服务器信息
type YggdrasilServerInfo struct {
	Meta  YggdrasilServerMeta  `json:"meta"`
	Links YggdrasilServerLinks `json:"links"`
}

// normalizeYggdrasilURL 规范化 Yggdrasil 服务器地址
func normalizeYggdrasilURL(serverURL string) string {
	serverURL = strings.TrimSpace(serverURL)
	serverURL = strings.TrimSuffix(serverURL, "/")
	// 如果不以 /api/yggdrasil 结尾，自动添加
	if !strings.HasSuffix(serverURL, "/api/yggdrasil") {
		serverURL = serverURL + "/api/yggdrasil"
	}
	return serverURL
}

// GetYggdrasilServerInfo 获取 Yggdrasil 服务器信息
func (a *App) GetYggdrasilServerInfo(serverURL string) (*YggdrasilServerInfo, error) {
	serverURL = normalizeYggdrasilURL(serverURL)
	// 请求服务器根路径获取信息
	infoURL := strings.TrimSuffix(serverURL, "/api/yggdrasil")
	if !strings.HasSuffix(infoURL, "/") {
		infoURL += "/"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(infoURL)
	if err != nil {
		return nil, fmt.Errorf("无法连接到验证服务器: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取服务器信息失败: %v", err)
	}

	var info YggdrasilServerInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("解析服务器信息失败: %v", err)
	}

	return &info, nil
}

// LoginYggdrasil Yggdrasil 外置登录
func (a *App) LoginYggdrasil(serverURL string, username string, password string) (*ExternalAuthData, error) {
	serverURL = normalizeYggdrasilURL(serverURL)
	authURL := serverURL + "/authserver/authenticate"

	// 构建认证请求
	payload := map[string]interface{}{
		"agent": map[string]interface{}{
			"name":    "Minecraft",
			"version": 1,
		},
		"username":    username,
		"password":    password,
		"requestUser": true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("构建请求失败: %v", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("POST", authURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接验证服务器失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	var authResp YggdrasilAuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	// 检查错误
	if authResp.Error != "" {
		errMsg := authResp.ErrorMessage
		if errMsg == "" {
			errMsg = authResp.Error
		}
		if authResp.Error == "ForbiddenOperationException" {
			return nil, fmt.Errorf("用户名或密码错误")
		}
		return nil, fmt.Errorf("登录失败: %s", errMsg)
	}

	if authResp.AccessToken == "" {
		return nil, fmt.Errorf("登录失败: 未获取到访问令牌")
	}

	// 获取选中的角色
	var playerName string
	var playerUUID string
	if authResp.SelectedProfile != nil {
		playerName = authResp.SelectedProfile.Name
		playerUUID = authResp.SelectedProfile.ID
	} else if len(authResp.AvailableProfiles) > 0 {
		playerName = authResp.AvailableProfiles[0].Name
		playerUUID = authResp.AvailableProfiles[0].ID
	} else {
		return nil, fmt.Errorf("该账号还没有创建角色，请先在皮肤站创建角色")
	}

	// 获取服务器名称
	serverName := ""
	serverInfo, infoErr := a.GetYggdrasilServerInfo(serverURL)
	if infoErr == nil && serverInfo.Meta.ServerName != "" {
		serverName = serverInfo.Meta.ServerName
	}

	return &ExternalAuthData{
		ServerURL:   serverURL,
		AccessToken: authResp.AccessToken,
		ClientToken: authResp.ClientToken,
		UUID:        playerUUID,
		Username:    playerName,
		Password:    password,
		ServerName:  serverName,
	}, nil
}

// RefreshExternalToken 刷新外置登录令牌
func (a *App) RefreshExternalToken(username string) error {
	authData, err := a.GetExternalAuthData(username)
	if err != nil {
		return fmt.Errorf("获取外置认证数据失败: %v", err)
	}

	// 尝试 refresh 端点
	refreshURL := authData.ServerURL + "/authserver/refresh"

	payload := map[string]interface{}{
		"accessToken":  authData.AccessToken,
		"clientToken":  authData.ClientToken,
		"requestUser":  true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("构建请求失败: %v", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("POST", refreshURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("连接验证服务器失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	var authResp YggdrasilAuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}

	if authResp.Error != "" {
		// refresh 失败，尝试用密码重新登录
		if authData.Password != "" {
			newAuthData, loginErr := a.LoginYggdrasil(authData.ServerURL, authData.Username, authData.Password)
			if loginErr != nil {
				return fmt.Errorf("令牌刷新失败且重新登录失败: %v", loginErr)
			}
			newAuthData.ServerURL = authData.ServerURL
			newAuthData.ServerName = authData.ServerName
			return a.SaveExternalAuthData(username, newAuthData)
		}
		return fmt.Errorf("令牌刷新失败: %s", authResp.ErrorMessage)
	}

	// 更新令牌
	authData.AccessToken = authResp.AccessToken
	if authResp.ClientToken != "" {
		authData.ClientToken = authResp.ClientToken
	}
	if authResp.SelectedProfile != nil {
		authData.UUID = authResp.SelectedProfile.ID
		authData.Username = authResp.SelectedProfile.Name
	}

	return a.SaveExternalAuthData(username, authData)
}

// DownloadAuthlibInjector 下载 authlib-injector.jar
func (a *App) DownloadAuthlibInjector() (string, error) {
	qglDir := a.GetQGLDir()
	jarPath := filepath.Join(qglDir, "authlib-injector.jar")

	// 如果已存在，直接返回
	if _, err := os.Stat(jarPath); err == nil {
		return jarPath, nil
	}

	if err := os.MkdirAll(qglDir, 0755); err != nil {
		return "", fmt.Errorf("创建目录失败: %v", err)
	}

	// 参考 PCL：先获取 latest.json 获取下载地址，再下载 jar
	latestURLs := []string{
		"https://authlib-injector.yushi.moe/artifact/latest.json",
		"https://bmclapi2.bangbang93.com/mirrors/authlib-injector/artifact/latest.json",
	}

	var latestInfo map[string]interface{}
	var downloadURL string

	client := &http.Client{Timeout: 15 * time.Second}
	for _, url := range latestURLs {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			if err := json.Unmarshal(body, &latestInfo); err == nil {
				if du, ok := latestInfo["download_url"].(string); ok && du != "" {
					downloadURL = du
					break
				}
			}
		}
	}

	if downloadURL == "" {
		return "", fmt.Errorf("获取 authlib-injector 下载地址失败")
	}

	// 替换为 BMCLAPI 镜像作为备用
	mirrorURL := strings.ReplaceAll(downloadURL, "authlib-injector.yushi.moe", "bmclapi2.bangbang93.com/mirrors/authlib-injector")

	downloadClient := &http.Client{Timeout: 120 * time.Second}
	var lastErr error
	for _, url := range []string{downloadURL, mirrorURL} {
		resp, err := downloadClient.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		file, err := os.Create(jarPath)
		if err != nil {
			return "", fmt.Errorf("创建文件失败: %v", err)
		}
		if _, err := io.Copy(file, resp.Body); err != nil {
			file.Close()
			os.Remove(jarPath)
			return "", fmt.Errorf("写入文件失败: %v", err)
		}
		file.Close()
		return jarPath, nil
	}

	return "", fmt.Errorf("下载 authlib-injector 失败: %v", lastErr)
}

// GetAuthlibInjectorPath 获取 authlib-injector.jar 路径（不存在则下载）
func (a *App) GetAuthlibInjectorPath() (string, error) {
	return a.DownloadAuthlibInjector()
}
