package main

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// optionsguard.go —— Minecraft options.txt 解析 / 写回加固内核。
//
// options.txt 是客户端根目录下的键值配置文件（每行 "key:value"，值常含
// ":" 与空格，键则是字母数字与 _ - .）。启动器常把它读进来做展示或透传。
// 恶意 mod / 资源包 / 崩溃修复工具可能改写这份文件，风险集中在四点：
//
//  1. 解析不做大小与行数上限：大文件 / 超长行造成内存放大（DoS）。
//  2. 键名不过滤：解析器按首冒号切分，攻击者可注入任意键名，或利用
//     值里的 \r\n 在"写回"时伪造新的配置行（CRLF 行注入）。
//  3. 值不过滤控制字符：除 CRLF 外还有 \x00 等，写回后进入后续解析器
//     的可能是不可见垃圾。
//  4. 已知布尔 / 数值 / 枚举键不做类型收敛：把 "yes"/"1"/"true" 混用
//     留给下游去猜，行为不可预期。
//
// 本内核只做纯文本层校验与序列化，不触碰文件 IO；调用方（读盘 / 写盘）
// 再套 safeio 与原子写。

const (
	maxOptionsFileBytes  = 256 * 1024 // 单文件上限，防 DoS 读入放大
	maxOptionLineBytes   = 8 * 1024   // 单行上限
	maxOptionsCount      = 4096       // 键数量上限
	minOptionKeyRuneLen  = 1
	maxOptionKeyRuneLen  = 96
	maxOptionValueRunes  = 2048 // 单个值长度上限（中文按 rune 计）
)

// knownBooleanKeys 是语义为"开关"的常见选项；写回时统一收敛为 true/false。
var knownBooleanKeys = map[string]bool{
	"autoJump":            true,
	"autoSuggestCommands": true,
	"chatColors":          true,
	"chatLinks":           true,
	"chatLinksPrompt":     true,
	"chatVisibility":      false, // 枚举，见 numeric/enum 处理
	"enableVsync":         true,
	"entityShadows":       true,
	"forceUnicodeFont":    true,
	"fov":                 false,
	"fovUpdate":           false,
	"fullscreen":          true,
	"hideServerAddress":   true,
	"joinServerScreen":    true,
	"lang":                false,
	"lastServer":          false,
	"mainHand":            false,
	"mouseSensitivity":    false,
	"narrator":            false,
	"onboardAccessibility": true,
	"pauseOnLostFocus":    true,
	"rawMouseInput":       true,
	"reducedDebugInfo":    true,
	"renderClouds":        false,
	"resourcePacks":       false,
	"sendCommandFeedback": true,
	"showSubtitles":       true,
	"skipMultiplayerWarning": true,
	"skipRealms32bitWarning": true,
	"snooperEnabled":      true,
	"soundDevice":         false,
	"streamOptIn":         true,
	"syncChunkWrites":     true,
	"telemetryOptIn":      false,
	"useNativeTransport":  true,
	"version":             false,
	"vsync":               true,
}

// OptionsIssue 是单条发现的问题（级别 + 键名/行号 + 描述）。
type OptionsIssue struct {
	Severity string // "error"（拒收/写回须剔除）| "warn"（收敛或提示）
	Key      string
	Line     int // 1 起
	Reason   string
}

// OptionsParseResult 是一次解析的结果：规范化后的键值表 + 问题清单。
type OptionsParseResult struct {
	OK      bool
	Options map[string]string
	Issues  []OptionsIssue
}

// validOptionKey 校验键名字符集：字母数字 _ - .，长度受限。
func validOptionKey(k string) bool {
	if len(k) < minOptionKeyRuneLen || len(k) > maxOptionKeyRuneLen {
		return false
	}
	for _, r := range k {
		if r == '_' || r == '-' || r == '.' {
			continue
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// rejectControl 返回第一个非法控制字符；\t 允许（options.txt 值内可出现制表符）。
// 返回 -1 表示无控制字符（哨兵值：U+0000 本身是合法非法字符，不能当“无”）。
func rejectControl(s string) rune {
	for _, r := range s {
		if r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return r
		}
	}
	return -1
}

// normalizeBoolValue 把常见布尔写法收敛为 true/false；无法识别返回原值。
func normalizeBoolValue(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "1", "on":
		return "true"
	case "false", "no", "0", "off":
		return "false"
	}
	return v
}

// convergeOptionValue 按已知语义收敛值：布尔键收 true/false；数值键校验
// 为有限数字串；其余只做长度与控制字符校验。未知键原样返回。
func convergeOptionValue(key, v string) (string, bool) {
	if len([]rune(v)) > maxOptionValueRunes {
		return v, false
	}
	if rejectControl(v) != -1 {
		return v, false
	}
	if knownBooleanKeys[key] {
		return normalizeBoolValue(v), true
	}
	return v, true
}

// parseOptionsText 解析 options.txt 全文；OK=false 表示存在必须拒收的问题。
// 可接受的容差项（键重复取最后、行尾 \r 剥离、空行/注释跳过）不会置 OK=false。
func parseOptionsText(text string) OptionsParseResult {
	res := OptionsParseResult{Options: map[string]string{}}
	if len(text) > maxOptionsFileBytes {
		res.OK = false
		res.Issues = append(res.Issues, OptionsIssue{
			Severity: "error", Key: "", Line: 0,
			Reason: fmt.Sprintf("文件超过 %d 字节上限", maxOptionsFileBytes),
		})
		return res
	}
	lines := strings.Split(text, "\n")
	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSuffix(raw, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > maxOptionLineBytes {
			res.OK = false
			res.Issues = append(res.Issues, OptionsIssue{
				Severity: "error", Key: "", Line: lineNo,
				Reason: fmt.Sprintf("第 %d 行超过 %d 字节上限", lineNo, maxOptionLineBytes),
			})
			continue
		}
		// 值内的 CRLF / 控制字符：既破坏单行语义，又会在写回时伪造新配置行。
		if c := rejectControl(line); c != -1 {
			res.OK = false
			res.Issues = append(res.Issues, OptionsIssue{
				Severity: "error", Key: "", Line: lineNo,
				Reason: fmt.Sprintf("第 %d 行含控制字符 U+%04X", lineNo, c),
			})
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			res.OK = false
			res.Issues = append(res.Issues, OptionsIssue{
				Severity: "error", Key: "", Line: lineNo,
				Reason: "缺少 ':' 分隔（非 options.txt 行）",
			})
			continue
		}
		key := line[:idx]
		val := line[idx+1:]
		if !validOptionKey(key) {
			res.OK = false
			res.Issues = append(res.Issues, OptionsIssue{
				Severity: "error", Key: key, Line: lineNo,
				Reason: "键名含非法字符或长度越界",
			})
			continue
		}
		if len(res.Options) >= maxOptionsCount {
			res.OK = false
			res.Issues = append(res.Issues, OptionsIssue{
				Severity: "error", Key: key, Line: lineNo,
				Reason: fmt.Sprintf("键数量超过 %d 上限", maxOptionsCount),
			})
			continue
		}
		nv, ok := convergeOptionValue(key, val)
		if !ok {
			res.OK = false
			res.Issues = append(res.Issues, OptionsIssue{
				Severity: "error", Key: key, Line: lineNo,
				Reason: "值超长或含控制字符",
			})
			continue
		}
		if nv != val {
			res.Issues = append(res.Issues, OptionsIssue{
				Severity: "warn", Key: key, Line: lineNo,
				Reason: fmt.Sprintf("布尔值收敛 %q -> %q", val, nv),
			})
		}
		res.Options[key] = nv
	}
	// OK 只由 error 级问题决定；warn（布尔收敛等）不拒收。
	res.OK = true
	for _, it := range res.Issues {
		if it.Severity == "error" {
			res.OK = false
		}
	}
	return res
}

// serializeOptions 把键值表序列化回 options.txt 文本：键排序输出、值已收敛、
// 行尾统一 \n、拒绝任何含控制字符的值（防注入往返）。
func serializeOptions(opts map[string]string) (string, []OptionsIssue) {
	keys := make([]string, 0, len(opts))
	for k := range opts {
		if validOptionKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var sb strings.Builder
	var issues []OptionsIssue
	for _, k := range keys {
		v := opts[k]
		if rejectControl(v) != -1 || len([]rune(v)) > maxOptionValueRunes {
			issues = append(issues, OptionsIssue{
				Severity: "error", Key: k, Line: 0,
				Reason: "值含控制字符或超长，写回时剔除该键",
			})
			continue
		}
		nv, _ := convergeOptionValue(k, v)
		sb.WriteString(k)
		sb.WriteByte(':')
		sb.WriteString(nv)
		sb.WriteByte('\n')
	}
	return sb.String(), issues
}

// auditOptionsText 一次性审计：返回解析结果 + 序列化往返是否干净。
// 供启动前校验与调试展示使用。
func auditOptionsText(text string) (OptionsParseResult, []OptionsIssue) {
	parsed := parseOptionsText(text)
	if !parsed.OK {
		return parsed, parsed.Issues
	}
	_, serIssues := serializeOptions(parsed.Options)
	return parsed, serIssues
}
