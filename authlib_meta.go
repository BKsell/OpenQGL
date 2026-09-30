package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

// authlib-injector.jar 是通过 -javaagent 加载进游戏 JVM 的可执行字节码，
// 一旦被篡改 / 替换就是代码执行（RCE）。它的信任锚是官方 latest.json 给出的
// SHA-256（不是 Mojang 的 SHA-1），因此不能复用 cachemeta.go 那套以 SHA-1 为锚
// 的侧车，单独维护一个只认 SHA-256 的元数据文件。
//
// 侧车与 jar 同目录、同权限（0600），记录权威 SHA-256 与字节数：
// 每次启动若 jar 已存在，先用它做廉价尺寸预检 + 强哈希复核，通过才复用，
// 杜绝"文件在就直接 -javaagent 跑"的旧行为。

type authlibMeta struct {
	SHA256 string `json:"sha256"` // 官方 latest.json 给出的权威 SHA-256（小写）
	Size   int64  `json:"size"`   // 字节数，先做廉价预检
}

func authlibMetaPath(jarPath string) string {
	return jarPath + ".sha256meta"
}

// loadAuthlibMeta 读取侧车；不存在或内容损坏时 ok=false（调用方应视为不可信）。
func loadAuthlibMeta(jarPath string) (authlibMeta, bool) {
	var m authlibMeta
	b, err := os.ReadFile(authlibMetaPath(jarPath))
	if err != nil {
		return m, false
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, false
	}
	if m.SHA256 == "" || m.Size <= 0 {
		return m, false
	}
	return m, true
}

// saveAuthlibMeta 在 jar 已通过官方 SHA-256 校验后原子写入侧车。
func saveAuthlibMeta(jarPath, expectedSHA256 string, size int64) error {
	m := authlibMeta{SHA256: expectedSHA256, Size: size}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := authlibMetaPath(jarPath) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, authlibMetaPath(jarPath)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func removeAuthlibMeta(jarPath string) {
	_ = os.Remove(authlibMetaPath(jarPath))
}

// sha256FileHex 计算文件的 SHA-256 小写十六进制摘要。
func sha256FileHex(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// verifyAuthlibJar 校验已存在的 jar 是否可直接复用：
// 侧车必须存在、尺寸必须一致、重新计算的 SHA-256 必须与侧车严格相等。
// 任何一项不满足都返回 false，由调用方删除并重新下载，绝不降级放行。
func verifyAuthlibJar(jarPath, expectedSHA256 string) bool {
	info, err := os.Stat(jarPath)
	if err != nil || info.Size() <= 0 {
		return false
	}
	expected := strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expected == "" {
		return false
	}
	meta, ok := loadAuthlibMeta(jarPath)
	if !ok {
		return false
	}
	if meta.Size != info.Size() {
		return false
	}
	if !hmac.Equal([]byte(meta.SHA256), []byte(expected)) {
		return false
	}
	got, err := sha256FileHex(jarPath)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(got), []byte(expected))
}
