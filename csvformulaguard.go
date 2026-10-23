package main

// csvformulaguard.go —— 导出 CSV/表格的公式注入（CSV injection）守卫。
//
// 背景：
//   启动器可把服务器列表、玩家名、mod 名导出为 CSV/日志表格。若单元格以 =、+、-、@、Tab、CR 开头，
//   Excel/LibreOffice/WPS 打开时会把它当公式执行，配合 =HYPERLINK/=cmd|' /c ...' 形成 DDE/命令执行。
//   本模块在"写单元格前"判定首字符并给出中性化方案；纯字符处理，不使用正则。

const (
	CSVReasonFormulaEquals = "csv-cell-begins-with-formula-equals"
	CSVReasonFormulaPlus   = "csv-cell-begins-with-formula-plus"
	CSVReasonFormulaMinus  = "csv-cell-begins-with-formula-minus"
	CSVReasonFormulaAt     = "csv-cell-begins-with-formula-at"
	CSVReasonLeadingTabCR  = "csv-cell-begins-with-tab-or-carriage-return"
	CSVReasonDDECmd        = "csv-cell-contains-dde-or-cmd-pipe-execution"
)

// CSVFinding 记录一处问题。
type CSVFinding struct {
	Reason string
	Column int
}

// CSVIsDangerousStart 判定单元格首字符是否触发公式解析。
func CSVIsDangerousStart(cell string) (dangerous bool, reason string) {
	if cell == "" {
		return false, ""
	}
	switch cell[0] {
	case '=':
		return true, CSVReasonFormulaEquals
	case '+':
		return true, CSVReasonFormulaPlus
	case '-':
		return true, CSVReasonFormulaMinus
	case '@':
		return true, CSVReasonFormulaAt
	case '\t', '\r':
		return true, CSVReasonLeadingTabCR
	}
	return false, ""
}

// CSVAuditCell 审计单个单元格。col 仅用于定位。
func CSVAuditCell(cell string, col int) (safe bool, findings []CSVFinding) {
	if d, r := CSVIsDangerousStart(cell); d {
		findings = append(findings, CSVFinding{Reason: r, Column: col})
	}
	if csvContainsDDE(cell) {
		findings = append(findings, CSVFinding{Reason: CSVReasonDDECmd, Column: col})
	}
	return len(findings) == 0, findings
}

// CSVNeutralize 对危险单元格前置单引号（电子表格据此强制文本），安全单元格原样返回。
func CSVNeutralize(cell string) string {
	d, _ := CSVIsDangerousStart(cell)
	if d || csvContainsDDE(cell) {
		return "'" + cell
	}
	return cell
}

// CSVQuoteField 产出符合 RFC 4180 的字段：含逗号/引号/换行时用双引号包裹并把内部引号翻倍。
func CSVQuoteField(cell string) string {
	need := false
	for i := 0; i < len(cell); i++ {
		if cell[i] == ',' || cell[i] == '"' || cell[i] == '\n' || cell[i] == '\r' {
			need = true
			break
		}
	}
	if !need {
		return cell
	}
	out := make([]byte, 0, len(cell)+2)
	out = append(out, '"')
	for i := 0; i < len(cell); i++ {
		if cell[i] == '"' {
			out = append(out, '"', '"')
		} else {
			out = append(out, cell[i])
		}
	}
	out = append(out, '"')
	return string(out)
}

func csvContainsDDE(cell string) bool {
	low := csvLower(cell)
	// 常见 DDE/命令执行特征（不区分大小写的子串）
	needles := []string{"cmd|", "=cmd", "=hyper", "=webservice", "dde(", "|' /c"}
	for _, n := range needles {
		if csvHasSub(low, n) {
			return true
		}
	}
	return false
}

func csvLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func csvHasSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// CSVHasReason 判定结果含某类问题。
func CSVHasReason(findings []CSVFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
