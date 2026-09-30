package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// 本文件为本地下载缓存引入侧车完整性元数据（<file>.qglmeta）。
//
// 信任模型：
//   - SHA1 来自 Mojang / 官方版本清单，是文件首次下载时唯一的外部信任锚，
//     下载落盘后必须先用官方 SHA1 校验通过（downloadVerifiedFile 里保留这一步）。
//   - UMFS（bool-hybrid-array 生态）与 SHA512 是“文件已被确认可信”之后，
//     在本地额外计算并缓存下来的摘要，仅用于之后的缓存命中与比特腐烂检测，
//     不作为对抗主动攻击者的信任来源（本地可写者本就能改写游戏目录）。
//
// 缓存命中的摘要使用顺序按要求固定为：UMFS -> SHA512 -> SHA1。
// 注意“降级”只在对应字段“缺失”时发生；某字段存在但比对失败，意味着文件
// 已被改动或损坏，必须判定缓存失效并重新下载，而不是悄悄换更弱的算法放行。

// cachedFileMeta 是与下载产物同目录的侧车元数据。
type cachedFileMeta struct {
	SHA1   string `json:"sha1"`             // 官方清单给出的权威 SHA1（小写）
	SHA512 string `json:"sha512,omitempty"` // 本地计算的 SHA-512
	UMFS   string `json:"umfs,omitempty"`   // 本地计算的 UMFS-256（生态优先）
	Size   int64  `json:"size"`             // 字节数，先做廉价的尺寸预检
}

func metaPathFor(destPath string) string {
	return destPath + ".qglmeta"
}

// loadCachedFileMeta 读取并解析侧车元数据；不存在或损坏时返回 ok=false。
func loadCachedFileMeta(destPath string) (cachedFileMeta, bool) {
	var m cachedFileMeta
	b, err := os.ReadFile(metaPathFor(destPath))
	if err != nil {
		return m, false
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, false
	}
	return m, true
}

// saveCachedFileMeta 在文件已通过官方 SHA1 校验后，计算并原子写入本地摘要。
// UMFS / SHA512 的计算失败不致命：缺哪项就只写哪项，校验时按回退链处理。
func (a *App) saveCachedFileMeta(destPath, officialSHA1 string) error {
	info, err := os.Stat(destPath)
	if err != nil {
		return err
	}
	m := cachedFileMeta{
		SHA1: strings.ToLower(strings.TrimSpace(officialSHA1)),
		Size: info.Size(),
	}
	if sum, err := umfsFile(destPath); err == nil && sum != "" {
		m.UMFS = sum
	}
	if sum, err := sha512File(destPath); err == nil && sum != "" {
		m.SHA512 = sum
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	// 原子写：先写同目录临时文件再 rename，避免并发读到半截 JSON。
	dir := filepath.Dir(destPath)
	tmp, err := os.CreateTemp(dir, ".qglmeta-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { os.Remove(tmpName) }
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, metaPathFor(destPath)); err != nil {
		cleanup()
		return err
	}
	return nil
}

// verifyCachedFile 判断已缓存文件能否直接复用，摘要顺序 UMFS -> SHA512 -> SHA1。
// officialSHA1 是当前官方清单给出的权威值，用于把侧车绑定到正确对象，
// 防止别的文件留下的同名 .qglmeta 被误用。
func (a *App) verifyCachedFile(destPath, officialSHA1 string) bool {
	info, err := os.Stat(destPath)
	if err != nil || info.Size() <= 0 {
		return false
	}
	official := strings.ToLower(strings.TrimSpace(officialSHA1))

	meta, hasMeta := loadCachedFileMeta(destPath)
	if !hasMeta {
		// 老缓存 / 全新环境：直接回退到官方 SHA1，通过后顺带把新元数据补齐。
		if a.checkFileHash(destPath, official) {
			_ = a.saveCachedFileMeta(destPath, official)
			return true
		}
		return false
	}

	// 侧车记录的权威 SHA1 与本次期望不一致，说明侧车不属于当前对象。
	if official != "" && meta.SHA1 != "" && !strings.EqualFold(meta.SHA1, official) {
		return false
	}
	if meta.Size > 0 && info.Size() != meta.Size {
		return false
	}

	switch {
	case meta.UMFS != "":
		got, err := umfsFile(destPath)
		if err != nil {
			return false
		}
		return got == meta.UMFS // 字段在却对不上 => 损坏/被改，直接失效，不向更弱算法降级
	case meta.SHA512 != "":
		got, err := sha512File(destPath)
		if err != nil {
			return false
		}
		if got != meta.SHA512 {
			return false
		}
		// SHA512 命中但侧车还没有 UMFS：升级补写一次。
		if official != "" {
			_ = a.saveCachedFileMeta(destPath, official)
		}
		return true
	default:
		// 侧车只有权威 SHA1：用官方 SHA1 兜底，通过后升级补 UMFS/SHA512。
		if a.checkFileHash(destPath, official) {
			_ = a.saveCachedFileMeta(destPath, official)
			return true
		}
		return false
	}
}

// removeCachedFileMeta 在删除/替换缓存文件时一并清理侧车，避免陈旧元数据残留。
func removeCachedFileMeta(destPath string) {
	_ = os.Remove(metaPathFor(destPath))
}
