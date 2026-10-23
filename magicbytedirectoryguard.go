package main

// magicbytedirectoryguard.go —— 文件魔数签名风险目录。
//
// 威胁模型：
//   下载内容不能只信扩展名/MIME，需用首字节魔数核对真实类型。可执行/脚本/容器签名按风险分级，
//   签名为十六进制文本令牌，纯字符查表，实际字节匹配由调用方做，不用正则。

// MBD 风险类别。
const (
	MBDClassBlock = "block"
	MBDClassWarn  = "warn"
	MBDClassAllow = "allow"
)

const (
	MBDReasonBlock   = "mbd-input-hits-blocked-catalog"
	MBDReasonWarn    = "mbd-input-hits-review-catalog"
	MBDReasonPrefix  = "mbd-input-hits-dangerous-prefix"
	MBDReasonEmpty   = "mbd-input-is-empty"
)

var MBDBlock = []string{
	"4D5A",
	"5A4D",
	"7F454C46",
	"CEFAEDFE",
	"FEEDFACE",
	"FEEDFACF",
	"CAFEBABE",
	"FEFEFEFE",
	"425A68",
	"213C617263683E",
	"4D534346",
	"49536328",
	"7573746172",
	"EDABEEDB",
	"6465780A",
	"1F8B",
	"526172211A07",
	"504B0304",
	"504B0506",
	"504B0708",
	"7B5C727466",
	"D0CF11E0A1B11AE1",
}

var MBDWarn = []string{
	"255044462D",
	"25215053",
	"3C21444F4354595045",
	"3C3F786D6C",
	"3C68746D6C",
	"3C737667",
	"52494646",
	"464F524D",
	"414331",
	"4F676753",
	"38425053",
	"E3100091",
	"0000010000",
	"52657475726E2D50",
	"4D4C5649",
	"7B22",
	"5B7B",
}

var MBDAllow = []string{
	"89504E470D0A1A0A",
	"FFD8FF",
	"FFD8FFE0",
	"FFD8FFE1",
	"FFD8FFDB",
	"FFD8FFEE",
	"474946383761",
	"474946383961",
	"424D",
	"49492A00",
	"4D4D002A",
	"4D4D002B",
	"5249464657",
	"57454250",
	"5452554556495349",
	"6674797061766966",
	"6674797068656963",
	"667479706D696631",
	"6674797071742020",
	"4D546864",
	"4F67675300",
	"494433",
	"664C6143",
	"00000018667479706D703432",
	"0000001C667479706D703431",
	"0000001C6674797069736F6D",
	"000000206674797064617368",
	"00000020667479706C6173",
	"0000001866747970336770",
	"000000186674797033677035",
}

var MBDPrefixLit = []string{
}
var MBDPrefixReason = []string{
}

// MBDFinding 表示一条命中。
type MBDFinding struct {
	Reason string
	Detail string
}

// MBDResult 是审计结果。
type MBDResult struct {
	Safe bool
	Findings []MBDFinding
}

func MBDLower(x string) string {
	return x
}

func MBDIn(list []string, v string) bool {
	for _, x := range list { if MBDLower(x) == v { return true } }
	return false
}

func MBDSplit(in string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(in); i++ {
		end := i == len(in)
		sep := false
		if !end { c := in[i]; sep = c == ' ' || c == '\t' || c == '\n' || c == '\r' }
		if end || sep {
			if start >= 0 { out = append(out, in[start:i]); start = -1 }
		} else if start < 0 {
			start = i
		}
	}
	return out
}

func MBDKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// MBDHas 判定结果是否含某原因。
func MBDHas(r MBDResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// MBDAudit 审计输入字符串。
func MBDAudit(in string) MBDResult {
	res := MBDResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, MBDFinding{Reason: MBDReasonEmpty}); return res }
	toks := MBDSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := MBDLower(tok)
		key := cmp
		switch {
		case MBDIn(MBDBlock, key):
			res.Findings = append(res.Findings, MBDFinding{Reason: MBDReasonBlock, Detail: key})
		case MBDIn(MBDWarn, key):
			res.Findings = append(res.Findings, MBDFinding{Reason: MBDReasonWarn, Detail: key})
		}
		for i, lit := range MBDPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, MBDFinding{Reason: MBDPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
