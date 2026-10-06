package main

// BMCLAPI 镜像换源内核（mirror rewrite core）。
//
// 历史问题：把 Mojang / 各 Maven 官方主机改写为 BMCLAPI 镜像的 strings.Replace
// 散落在 minecraft.go / loader.go / server.go 二十余处，同一条源主机在不同物
// 类型下还要落到不同镜像路径，极易写错：
//   - 版本 / 资源索引 JSON：piston-meta、launcher 主机落到镜像根；
//   - 服务端 jar、Mappings：piston-data、launcher 主机落到镜像根（保留 /v1/...）；
//   - getMirrorURLs 的 Mojang 对象：三个对象主机的 /v1/objects/ 专门落到 /version/；
//   - libraries.minecraft.net 在"版本清单换源"里映射到 /maven，在库下载镜像里
//     却映射到 /libraries（BMCLAPI 对这两类内容是两套路由，不能合并）；
//   - Forge / NeoForge（源前缀带 /releases）/ Fabric / Maven Central 各有前缀。
//
// 因此本文件只提供"按有序前缀对做字面替换"的纯内核，并为每类调用场景固定规则
// 集。规则每条至多替换一次，等价历史 strings.Replace(url, from, to, 1)；同一条
// URL 只有一个主机，规则集内并列的多条主机规则至多命中一条，顺序不影响结果，
// 但更具体的长路径前缀（如 /v1/objects/）必须由对应场景的规则集单独承载。

import "strings"

// bmclMirrorBase 是 BMCLAPI 镜像的固定根地址（仅 https）。
const bmclMirrorBase = "https://bmclapi2.bangbang93.com"

// urlPrefixRule 表示一条字面前缀替换规则：字符串以 from 开头的片段替换为 to。
type urlPrefixRule struct {
	from string
	to   string
}

// rewriteURLPrefixes 按给定顺序依次应用前缀替换，每条最多替换一次，
// 与历史手写 strings.Replace(url, from, to, 1) 行为完全一致；命中不到的规则跳过。
func rewriteURLPrefixes(raw string, rules []urlPrefixRule) string {
	out := raw
	for _, rule := range rules {
		if rule.from == "" {
			continue
		}
		out = strings.Replace(out, rule.from, rule.to, 1)
	}
	return out
}

// bmclLauncherPrefixRules 供版本清单 / 版本 JSON / 库与资产索引 URL 换源：
// piston-meta、launcher 落到镜像根；libraries.minecraft.net 落到 /maven。
var bmclLauncherPrefixRules = []urlPrefixRule{
	{"https://piston-meta.mojang.com", bmclMirrorBase},
	{"https://launcher.mojang.com", bmclMirrorBase},
	{"https://libraries.minecraft.net", bmclMirrorBase + "/maven"},
}

// rewriteLauncherURLToBMCL 等价原 minecraft.go 的 replaceWithBMCLAPI。
func rewriteLauncherURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclLauncherPrefixRules)
}

// bmclMetaIndexPrefixRules 供服务端版本 JSON 与客户端资源索引 JSON：
// piston-meta、launcher 主机整体落到镜像根（保留其下 /v1/... 路径）。
var bmclMetaIndexPrefixRules = []urlPrefixRule{
	{"https://piston-meta.mojang.com", bmclMirrorBase},
	{"https://launcher.mojang.com", bmclMirrorBase},
}

// rewriteMetaIndexURLToBMCL 把元数据 / 索引主机换到镜像根。
func rewriteMetaIndexURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMetaIndexPrefixRules)
}

// bmclMappedDataPrefixRules 供服务端 jar 与 Mappings 文件：piston-data、launcher
// 主机整体落到镜像根（保留 /v1/objects/... 路径，不做 /version 收敛）。
var bmclMappedDataPrefixRules = []urlPrefixRule{
	{"https://piston-data.mojang.com", bmclMirrorBase},
	{"https://launcher.mojang.com", bmclMirrorBase},
}

// rewriteMappedDataURLToBMCL 把对象存储主机换到镜像根。
func rewriteMappedDataURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMappedDataPrefixRules)
}

// bmclMavenLibPrefixRules 供 Forge / NeoForge / Fabric 安装器解析出的 Maven 库：
// 三个 Maven 主机统一落到镜像 /maven/（NeoForge 源前缀带 /releases）。
var bmclMavenLibPrefixRules = []urlPrefixRule{
	{"https://maven.minecraftforge.net/", bmclMirrorBase + "/maven/"},
	{"https://maven.neoforged.net/releases/", bmclMirrorBase + "/maven/"},
	{"https://maven.fabricmc.net/", bmclMirrorBase + "/maven/"},
}

// rewriteMavenLibURLToBMCL 把三大模组 Maven 主机换到镜像 /maven/。
func rewriteMavenLibURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMavenLibPrefixRules)
}

// bmclFabricLibPrefixRules 供 Fabric profile 库：fabric 与 Maven Central 落 /maven/，
// libraries.minecraft.net 落 /libraries/（库下载路由，与清单换源的 /maven 不同）。
var bmclFabricLibPrefixRules = []urlPrefixRule{
	{"https://maven.fabricmc.net/", bmclMirrorBase + "/maven/"},
	{"https://repo1.maven.org/maven2/", bmclMirrorBase + "/maven/"},
	{"https://libraries.minecraft.net/", bmclMirrorBase + "/libraries/"},
}

// rewriteFabricLibURLToBMCL 把 Fabric profile 库列表的主机换到镜像。
func rewriteFabricLibURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclFabricLibPrefixRules)
}

// bmclMavenCentralPrefixRules 供 getMirrorURLs 的 Maven Central 分支。
var bmclMavenCentralPrefixRules = []urlPrefixRule{
	{"https://repo1.maven.org/maven2/", bmclMirrorBase + "/maven/"},
}

// rewriteMavenCentralURLToBMCL 把 Maven Central 换到镜像 /maven/。
func rewriteMavenCentralURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMavenCentralPrefixRules)
}

// bmclLibraryArtifactPrefixRules 供 getMirrorURLs 的 libraries.minecraft.net 分支，
// 库下载落到镜像 /libraries/。
var bmclLibraryArtifactPrefixRules = []urlPrefixRule{
	{"https://libraries.minecraft.net/", bmclMirrorBase + "/libraries/"},
}

// rewriteLibraryArtifactURLToBMCL 把 libraries.minecraft.net 库对象换到 /libraries/。
func rewriteLibraryArtifactURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclLibraryArtifactPrefixRules)
}

// bmclObjectVersionPrefixRules 供 getMirrorURLs 的 Mojang 对象分支：三个对象主机
// 的 /v1/objects/ 前缀统一落到镜像 /version/（只替换该段路径，前缀不匹配时不动）。
var bmclObjectVersionPrefixRules = []urlPrefixRule{
	{"https://launcher.mojang.com/v1/objects/", bmclMirrorBase + "/version/"},
	{"https://piston-data.mojang.com/v1/objects/", bmclMirrorBase + "/version/"},
	{"https://piston-meta.mojang.com/v1/objects/", bmclMirrorBase + "/version/"},
}

// rewriteObjectVersionURLToBMCL 把 Mojang 对象存储的 /v1/objects/ 换到 /version/。
func rewriteObjectVersionURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclObjectVersionPrefixRules)
}

// bmclAssetPrefixRules 供资源对象（resources.download.minecraft.net）落 /assets/。
var bmclAssetPrefixRules = []urlPrefixRule{
	{"https://resources.download.minecraft.net/", bmclMirrorBase + "/assets/"},
}

// rewriteAssetURLToBMCL 把资源对象主机换到镜像 /assets/。
func rewriteAssetURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclAssetPrefixRules)
}
