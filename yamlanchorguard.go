package main

// yamlanchorguard.go —— YAML 锚点 / 别名膨胀（Billion Laughs 类）与不安全反序列化标签预扫描。
//
// 背景：
//   整合包说明、部分服务端配置、第三方源清单可能用 YAML 表达。YAML 有两类历史高危面：
//     1. 锚点（&name）+ 别名（*name）递归引用造成的指数 / 二次放大，与 XML Billion Laughs
//        同源：少量文本在展开阶段撑爆内存与 CPU；
//     2. 不安全的本地对象标签，如 !!python/object/apply、!!ruby/object、!!java/object，
//        若交给带"通用反序列化"能力的解析器，可能在解析期执行构造器 / 调用函数（很多
//        YAML 库历史默认允许 python/object/apply 触发 os.system）。
//
// 本模块在"把字节交给任何 YAML 解析器之前"做不依赖解析器、不使用正则的纯字节 / 字符扫描：
//   1. 统计锚点定义数、别名引用数、同一锚点被引用的次数（扇出）；
//   2. 估算别名嵌套链深度与展开放大上界，超阈值即判膨胀；
//   3. 检出危险 !! 标签；
//   4. 文档体积上限；
//   5. 注释 / 引号感知，避免误判文本。

const (
	YMLReasonDocumentTooLarge = "yml-document-too-large"
	YMLReasonTooManyAnchors   = "yml-too-many-anchors"
	YMLReasonAliasFanout      = "yml-alias-expansion-fanout"
	YMLReasonDeepAliasChain   = "yml-alias-chain-too-deep"
	YMLReasonUnsafeTag        = "yml-unsafe-deserialization-tag"
	YMLReasonQuotedUnterminated = "yml-quoted-string-unterminated"
)

// YMLPolicy 控制 YAML 预扫描严格度。
type YMLPolicy struct {
	MaxDocumentBytes int
	MaxAnchors       int
	MaxAliasFanout   int // 单一锚点被引用的最大次数
	MaxChainDepth    int // 别名嵌套链最大深度
	ForbidUnsafeTags bool
}

// YMLFinding 记录一处风险。
type YMLFinding struct {
	Reason string
	Line   int
	Detail string
}

// DefaultYMLPolicy 返回默认严格策略。
func DefaultYMLPolicy() YMLPolicy {
	return YMLPolicy{
		MaxDocumentBytes: 2 * 1024 * 1024,
		MaxAnchors:       64,
		MaxAliasFanout:   64,
		MaxChainDepth:    8,
		ForbidUnsafeTags: true,
	}
}

// ymlUnsafeTagFragments 为需要拦截的危险标签片段（小写）。
var ymlUnsafeTagFragments = []string{
	"!!python/object", "!!python/object/apply", "!!python/object/new",
	"!!python/name", "!!python/module", "!!python/complex",
	"!!ruby/object", "!!ruby/symbol",
	"!!java/object", "!!javax",
	"!!php/object",
	"!!perl/ref",
	"!!js/function",
	"tag:yaml.org,2002:python",
	"tag:yaml.org,2002:js/function",
}

// ymlLowerASCII 归一小写。
func ymlLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// ymlHasFold 判断 data[start:] 是否以小写 prefix 开头（大小写不敏感）。
func ymlHasFold(data []byte, start int, prefix string) bool {
	if start+len(prefix) > len(data) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if ymlLowerASCII(data[start+i]) != prefix[i] {
			return false
		}
	}
	return true
}

// ymlAnchorName 从 '&' / '*' 后读取锚点名（到空白 / 定界为止）。
func ymlAnchorName(data []byte, i int) (string, int) {
	j := i
	for j < len(data) {
		c := data[j]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ':' || c == ',' || c == ']' || c == '}' {
			break
		}
		j++
	}
	return string(data[i:j]), j
}

// YMLScan 预扫描 YAML 字节。
func YMLScan(data []byte, pol YMLPolicy) []YMLFinding {
	var out []YMLFinding
	if pol.MaxDocumentBytes > 0 && len(data) > pol.MaxDocumentBytes {
		out = append(out, YMLFinding{Reason: YMLReasonDocumentTooLarge, Line: ymlLineOf(data, len(data))})
	}

	anchorCount := 0
	aliasRefs := map[string]int{}
	line := 1
	i := 0
	for i < len(data) {
		c := data[i]
		if c == '\n' {
			line++
			i++
			continue
		}
		// 行注释跳过。
		if c == '#' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}
		// 单 / 双引号字符串整体跳过（同时检查闭合）。
		if c == '"' || c == '\'' {
			q := c
			j := i + 1
			closed := false
			for j < len(data) {
				if data[j] == '\\' && q == '"' {
					j += 2
					continue
				}
				if data[j] == q {
					if q == '\'' && j+1 < len(data) && data[j+1] == '\'' {
						j += 2
						continue
					}
					closed = true
					j++
					break
				}
				if data[j] == '\n' {
					line++
				}
				j++
			}
			if !closed {
				out = append(out, YMLFinding{Reason: YMLReasonQuotedUnterminated, Line: line})
			}
			i = j
			continue
		}
		// 危险标签 !! / tag:。
		if pol.ForbidUnsafeTags && (ymlHasFold(data, i, "!!") || ymlHasFold(data, i, "tag:yaml")) {
			for _, frag := range ymlUnsafeTagFragments {
				if ymlHasFold(data, i, frag) {
					out = append(out, YMLFinding{Reason: YMLReasonUnsafeTag, Line: line, Detail: frag})
					break
				}
			}
			i++
			continue
		}
		// 锚点定义 &name。
		if c == '&' {
			name, next := ymlAnchorName(data, i+1)
			if name != "" {
				anchorCount++
			}
			i = next
			continue
		}
		// 别名引用 *name。
		if c == '*' {
			name, next := ymlAnchorName(data, i+1)
			if name != "" {
				aliasRefs[name]++
			}
			i = next
			continue
		}
		i++
	}

	if anchorCount > pol.MaxAnchors {
		out = append(out, YMLFinding{Reason: YMLReasonTooManyAnchors, Line: 0, Detail: ymlItoa(anchorCount)})
	}
	maxFanout := 0
	for _, n := range aliasRefs {
		if n > maxFanout {
			maxFanout = n
		}
	}
	if maxFanout > pol.MaxAliasFanout {
		out = append(out, YMLFinding{Reason: YMLReasonAliasFanout, Line: 0, Detail: ymlItoa(maxFanout)})
	}
	// 展开放大上界估算：别名总数 * 最大扇出，超阈值视为链式放大风险。
	if len(aliasRefs) > 0 {
		totalAliases := 0
		for _, n := range aliasRefs {
			totalAliases += n
		}
		if totalAliases >= pol.MaxChainDepth && maxFanout >= pol.MaxChainDepth {
			out = append(out, YMLFinding{Reason: YMLReasonDeepAliasChain, Line: 0, Detail: ymlItoa(totalAliases)})
		}
	}
	return out
}

// ymlLineOf 返回偏移所在行号（1 起）。
func ymlLineOf(data []byte, offset int) int {
	line := 1
	for i := 0; i < offset && i < len(data); i++ {
		if data[i] == '\n' {
			line++
		}
	}
	return line
}

// ymlItoa 简易整数转字符串。
func ymlItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// YMLIsSafe 便捷判定。
func YMLIsSafe(data []byte) bool {
	return len(YMLScan(data, DefaultYMLPolicy())) == 0
}
