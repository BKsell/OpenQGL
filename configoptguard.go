package main

// configoptguard.go —— 来自远程/可被篡改配置文件的选项值校验守卫。
//
// 背景：
//   启动器的设置可被配置文件、整合包默认值、服务器下发参数影响。这些值若不校验就直接用，会变成
//   攻击旋钮或崩溃源：
//     - 数值类（内存 -Xmx、线程数、超时、并发、端口）：负数、0、超大值导致 OOM、除零、整数溢出；
//     - 布尔类被写成字符串 "false"/"0"/"no"，弱解析把任意非空串当 true（"false" 也成 true）；
//     - 字符串类（JVM 参数模板、下载基址、额外 classpath）超长或夹带换行/注入；
//     - 枚举类（GC、渲染、更新通道）接受任意值后落入未处理分支；
//     - "危险开关"：skipHashCheck、insecureTls、disableVerify、allowForeignOs、enableBetaURL，
//       远程配置不得能把这些安全开关悄悄打开。
//   本模块对一组配置项做类型/范围/危险开关校验，纯数值与字符串判定，不使用正则。

import "strings"

const (
	CFGReasonOutOfRange      = "config-numeric-option-out-of-range"
	CFGReasonNegativeOrZero  = "config-numeric-option-negative-or-zero"
	CFGReasonBoolCoercion    = "config-boolean-from-loose-string"
	CFGReasonStringTooLong   = "config-string-option-too-long"
	CFGReasonNewlineInValue  = "config-string-option-contains-newline"
	CFGReasonEnumInvalid     = "config-enum-option-not-allowed"
	CFGReasonDangerousToggle = "config-remote-attempt-to-enable-dangerous-toggle"
	CFGReasonTypeMismatch    = "config-option-type-mismatch"
)

// CFGKind 表示选项类型。
type CFGKind int

const (
	CFGKindInt CFGKind = iota
	CFGKindBool
	CFGKindString
	CFGKindEnum
)

// CFGSource 表示选项来源。
type CFGSource int

const (
	CFGSourceLocal  CFGSource = iota // 用户本地设置
	CFGSourceRemote                  // 远程/整合包/服务器下发
)

// CFGSpec 描述一个选项的约束。
type CFGSpec struct {
	Key       string
	Kind      CFGKind
	Min, Max  int64           // 数值范围
	MaxLen    int             // 字符串长度
	Allowed   map[string]bool // 枚举
	Dangerous bool            // 是否危险安全开关（远程不允许置 true）
}

// CFGValue 是待校验值（按 Kind 填对应字段）。
type CFGValue struct {
	IntVal  int64
	BoolVal bool
	StrVal  string
	// RawBoolString 非空表示布尔来自字符串弱解析输入，需要核对
	RawBoolString string
}

// CFGFinding 记录一处配置风险。
type CFGFinding struct {
	Reason string
	Key    string
	Detail string
}

// CFGEvaluate 校验单个选项。
func CFGEvaluate(spec CFGSpec, v CFGValue, source CFGSource) (safe bool, findings []CFGFinding) {
	add := func(reason, detail string) {
		findings = append(findings, CFGFinding{Reason: reason, Key: spec.Key, Detail: detail})
	}

	switch spec.Kind {
	case CFGKindInt:
		if v.IntVal < 0 && spec.Min >= 0 {
			add(CFGReasonNegativeOrZero, cfgItoa(v.IntVal))
		}
		if v.IntVal == 0 && spec.Min > 0 {
			add(CFGReasonNegativeOrZero, "0")
		}
		if spec.Min != spec.Max {
			if v.IntVal < spec.Min || v.IntVal > spec.Max {
				add(CFGReasonOutOfRange, cfgItoa(v.IntVal))
			}
		}
	case CFGKindBool:
		if v.RawBoolString != "" {
			s := strings.ToLower(strings.TrimSpace(v.RawBoolString))
			if s != "true" && s != "false" && s != "1" && s != "0" &&
				s != "yes" && s != "no" {
				add(CFGReasonBoolCoercion, s)
			}
			// 典型弱解析陷阱："false" 是长度>0 的字符串，会被当 true
			if s == "false" || s == "0" || s == "no" {
				if v.BoolVal {
					add(CFGReasonBoolCoercion, "false-parsed-true")
				}
			}
		}
		if spec.Dangerous && v.BoolVal && source == CFGSourceRemote {
			add(CFGReasonDangerousToggle, "remote-enabled")
		}
	case CFGKindString:
		if spec.MaxLen > 0 && len(v.StrVal) > spec.MaxLen {
			add(CFGReasonStringTooLong, cfgItoa(int64(len(v.StrVal))))
		}
		if strings.ContainsAny(v.StrVal, "\r\n") {
			add(CFGReasonNewlineInValue, "crlf")
		}
	case CFGKindEnum:
		if len(spec.Allowed) > 0 && !spec.Allowed[v.StrVal] {
			add(CFGReasonEnumInvalid, v.StrVal)
		}
	}
	return len(findings) == 0, findings
}

// CFGEvaluateMany 批量校验一组选项。
func CFGEvaluateMany(specs []CFGSpec, vals []CFGValue, sources []CFGSource) (safe bool, all []CFGFinding) {
	for i, s := range specs {
		src := CFGSourceLocal
		if i < len(sources) {
			src = sources[i]
		}
		var v CFGValue
		if i < len(vals) {
			v = vals[i]
		} else {
			all = append(all, CFGFinding{Reason: CFGReasonTypeMismatch, Key: s.Key, Detail: "missing"})
			continue
		}
		_, fs := CFGEvaluate(s, v, src)
		all = append(all, fs...)
	}
	return len(all) == 0, all
}

func cfgItoa(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
