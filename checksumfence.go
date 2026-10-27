package main

// checksumfence.go —— “这个下载该信哪种哈希”的选择策略（纯函数）。
//
// 约定：外部公开 API（Mojang、authlib、Modrinth）返回的校验值必须用它们声明的
// 原算法验（Mojang SHA1、authlib SHA256、Modrinth sha1/sha512），不能替换成
// 本地 UMFS；只有“本地自算、本地对账”的用途才用 UMFS。这里把这个选择集中成
// 一个函数，避免各下载点各写一句 if 又漂移。

import "strings"

// ChecksumSource 标记校验值来自哪里。
type ChecksumSource int

const (
	ChecksumUnknown ChecksumSource = iota
	ChecksumMojang
	ChecksumAuthlib
	ChecksumModrinth
	ChecksumLocalUMFS
)

// ChecksumAlgo 是最终该用的算法名。
type ChecksumAlgo string

const (
	AlgoSHA1   ChecksumAlgo = "sha1"
	AlgoSHA256 ChecksumAlgo = "sha256"
	AlgoSHA512 ChecksumAlgo = "sha512"
	AlgoLocal  ChecksumAlgo = "umfs"
)

// sourceFromHost 根据 host 判断校验值来源类别。
func sourceFromHost(host string) ChecksumSource {
	h := strings.ToLower(strings.TrimSpace(host))
	switch {
	case strings.Contains(h, "mojang.com") || strings.Contains(h, "minecraft.net"):
		return ChecksumMojang
	case strings.Contains(h, "authlib"):
		return ChecksumAuthlib
	case strings.Contains(h, "modrinth.com"):
		return ChecksumModrinth
	case h == "" || strings.HasPrefix(h, "127.") || strings.HasPrefix(h, "::1"):
		return ChecksumLocalUMFS
	}
	return ChecksumUnknown
}

// chooseChecksumAlgo 返回该源应当采用的主算法。
// 对 Modrinth 优先 sha512，缺失时降级 sha1；Mojang 主用 sha1；authlib 用 sha256。
func chooseChecksumAlgo(s ChecksumSource) ChecksumAlgo {
	switch s {
	case ChecksumMojang:
		return AlgoSHA1
	case ChecksumAuthlib:
		return AlgoSHA256
	case ChecksumModrinth:
		return AlgoSHA512
	case ChecksumLocalUMFS:
		return AlgoLocal
	default:
		return ""
	}
}

// isExternalAlgorithm 报告某算法是否属于外部 API 原生算法（不可替换为 UMFS）。
func isExternalAlgorithm(a ChecksumAlgo) bool {
	return a == AlgoSHA1 || a == AlgoSHA256 || a == AlgoSHA512
}
