package main

// manifestpinguard.go —— 版本/资源清单下载来源（repository）钉扎守卫。
//
// 背景：
//   启动器要按版本清单下载 client.jar、libraries、assets、natives 与 authlib 等。清单 JSON 里的
//   url 字段决定"从哪取这些文件"。一个被篡改/中间人/恶意镜像下发的清单，可把下载基址改成攻击者
//   主机，进而投放被植入的 jar。风险点：
//     - downloads/client/libraries/assetIndex 的 url 主机不在受信仓库集合内；
//     - 同一清单内不同条目指向不同主机（来源混杂），或出现明文 http；
//     - 跟随重定向后最终落盘来源主机与清单声明主机不一致（由 redirhdrguard 管跳转，这里管声明）；
//     - 自定义版本（整合包）覆盖官方 url 却未被用户显式信任；
//     - 清单通过非受信基址加载（version manifest 本身来源）。
//   外部 API 的哈希校验算法（Mojang SHA1、authlib SHA256、Modrinth sha1/sha512）保持原样，本模块
//   只做来源主机钉扎，纯字符串主机比较，不使用正则。

import "strings"

const (
	MPNReasonHostNotPinned           = "manifest-download-host-not-pinned"
	MPNReasonMixedHosts              = "manifest-mixed-download-hosts"
	MPNReasonPlainHTTP               = "manifest-download-over-plain-http"
	MPNReasonCustomOverrideUntrusted = "manifest-custom-url-override-untrusted"
	MPNReasonManifestOriginUnpinned  = "manifest-version-manifest-origin-unpinned"
	MPNReasonUserinfoInURL           = "manifest-url-contains-userinfo"
)

// MPNPolicy 设定受信仓库集合。
type MPNPolicy struct {
	PinnedHosts         map[string]bool // 允许的下载主机（小写，含端口）
	PinnedManifestHost  map[string]bool // version manifest 自身允许主机
	AllowCustomOverride bool
}

// MPNEntry 是清单中一个待下载条目。
type MPNEntry struct {
	Kind     string // client/library/asset/natives/authlib
	URL      string
	IsCustom bool // 是否来自整合包自定义覆盖
}

// MPNFinding 记录一处来源风险。
type MPNFinding struct {
	Reason string
	Detail string
}

// DefaultMPNPolicy 返回官方/常见 CDN 受信集合（示例集合，调用方可覆盖）。
func DefaultMPNPolicy() MPNPolicy {
	return MPNPolicy{
		PinnedHosts: map[string]bool{
			"piston-data.mojang.com":           true,
			"piston-meta.mojang.com":           true,
			"libraries.minecraft.net":          true,
			"resources.download.minecraft.net": true,
			"launcher.mojang.com":              true,
			"maven.fabricmc.net":               true,
			"meta.fabricmc.net":                true,
		},
		PinnedManifestHost: map[string]bool{
			"piston-meta.mojang.com":  true,
			"launchermeta.mojang.com": true,
			"meta.fabricmc.net":       true,
		},
	}
}

// mpnHostPort 提取小写 host（去协议、路径、userinfo）。
func mpnHostPort(raw string) (host string, scheme string, hasUserInfo bool) {
	s := strings.TrimSpace(raw)
	rest := s
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme = strings.ToLower(rest[:i])
		rest = rest[i+3:]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		if strings.IndexByte(rest[:at], '/') < 0 {
			hasUserInfo = true
			rest = rest[at+1:]
		}
	}
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	return strings.ToLower(rest), scheme, hasUserInfo
}

// MPNValidateManifestOrigin 校验 version manifest 自身来源。
func MPNValidateManifestOrigin(manifestURL string, policy MPNPolicy) (safe bool, findings []MPNFinding) {
	host, scheme, ui := mpnHostPort(manifestURL)
	if ui {
		findings = append(findings, MPNFinding{Reason: MPNReasonUserinfoInURL, Detail: host})
	}
	if scheme == "http" {
		findings = append(findings, MPNFinding{Reason: MPNReasonPlainHTTP, Detail: host})
	}
	if len(policy.PinnedManifestHost) > 0 && !policy.PinnedManifestHost[host] {
		findings = append(findings, MPNFinding{Reason: MPNReasonManifestOriginUnpinned, Detail: host})
	}
	return len(findings) == 0, findings
}

// MPNValidateEntries 校验清单内全部下载条目的来源钉扎。
func MPNValidateEntries(entries []MPNEntry, policy MPNPolicy) (safe bool, findings []MPNFinding) {
	hostSet := map[string]bool{}
	for _, e := range entries {
		host, scheme, ui := mpnHostPort(e.URL)
		if ui {
			findings = append(findings, MPNFinding{Reason: MPNReasonUserinfoInURL, Detail: e.Kind})
		}
		if scheme == "http" {
			findings = append(findings, MPNFinding{Reason: MPNReasonPlainHTTP, Detail: host})
		}
		if e.IsCustom {
			// 自定义覆盖需要独立信任：受信主机可以，非受信必须显式允许
			if len(policy.PinnedHosts) > 0 && !policy.PinnedHosts[host] && !policy.AllowCustomOverride {
				findings = append(findings, MPNFinding{Reason: MPNReasonCustomOverrideUntrusted,
					Detail: e.Kind + ":" + host})
			}
		} else if len(policy.PinnedHosts) > 0 && !policy.PinnedHosts[host] {
			findings = append(findings, MPNFinding{Reason: MPNReasonHostNotPinned,
				Detail: e.Kind + ":" + host})
		}
		hostSet[host] = true
	}
	if len(hostSet) > 1 {
		findings = append(findings, MPNFinding{Reason: MPNReasonMixedHosts,
			Detail: itoaMPN(len(hostSet)) + "-hosts"})
	}
	return len(findings) == 0, findings
}

func itoaMPN(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
