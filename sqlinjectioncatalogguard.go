package main

// sqlinjectioncatalogguard.go —— SQL 注入词法目录。
//
// 威胁模型：
//   拼接 SQL 前按词表识别注释符、布尔/联合/堆叠/时间盲注关键字与危险函数。分词后精确匹配 token，
//   纯字符，不解析 SQL，不用正则。

// SQL 风险类别。
const (
	SQLClassBlock = "block"
	SQLClassWarn  = "warn"
	SQLClassAllow = "allow"
)

const (
	SQLReasonBlock   = "sql-input-hits-blocked-catalog"
	SQLReasonWarn    = "sql-input-hits-review-catalog"
	SQLReasonPrefix  = "sql-input-hits-dangerous-prefix"
	SQLReasonEmpty   = "sql-input-is-empty"
)

var SQLBlock = []string{
	"--",
	"#",
	"/*",
	"*/",
	";",
	"'",
	"\"",
	"`)",
	"union",
	"select",
	"insert",
	"update",
	"delete",
	"drop",
	"alter",
	"create",
	"truncate",
	"exec",
	"execute",
	"sp_executesql",
	"xp_cmdshell",
	"sp_oacreate",
	"sp_oamethod",
	"information_schema",
	"sysobjects",
	"syscolumns",
	"systables",
	"sqlite_master",
	"pg_sleep",
	"benchmark",
	"waitfor",
	"delay",
	"load_file",
	"into",
	"outfile",
	"dumpfile",
	"0x",
	"char",
	"concat",
	"group_concat",
	"extractvalue",
	"updatexml",
	"convert",
	"cast",
	"having",
	"order",
	"group",
	"by",
	"or",
	"and",
	"xor",
	"not",
	"like",
	"between",
	"exists",
	"case",
	"when",
	"then",
	"else",
	"end",
	"if",
	"ifnull",
	"nullif",
	"sleep",
	"version",
	"database",
	"user",
	"current_user",
	"session_user",
	"system_user",
	"@@version",
	"@@hostname",
	"@@datadir",
	"@@basedir",
	"table_schema",
	"table_name",
	"column_name",
	"declare",
	"begin",
	"principals",
	"sys.databases",
	"master..",
	"openrowset",
	"opendatasource",
	"bulk",
	"administer",
	"dbcc",
	"shutdown",
}

var SQLWarn = []string{
	"limit",
	"offset",
	"distinct",
	"join",
	"inner",
	"outer",
	"left",
	"right",
	"cross",
	"natural",
	"where",
	"from",
	"as",
	"on",
	"in",
	"values",
	"set",
	"commit",
	"rollback",
	"savepoint",
	"grant",
	"revoke",
	"union-all",
	"regexp",
	"rlike",
	"soundex",
	"stored",
	"procedure",
	"function",
	"trigger",
	"view",
	"index",
	"temporary",
	"prepare",
	"deallocate",
	"cursor",
	"fetch",
	"while",
	"loop",
	"merge",
	"with",
	"cte",
	"explain",
	"describe",
	"show",
	"explain-analyze",
}

var SQLAllow = []string{
	"count",
	"sum",
	"avg",
	"min",
	"max",
	"abs",
	"round",
	"length",
	"lower",
	"upper",
	"trim",
	"substring",
	"replace",
	"now",
	"coalesce",
	"true",
	"false",
	"null",
	"asc",
	"desc",
	"primary",
	"key",
	"foreign",
	"references",
	"unique",
	"default",
	"auto_increment",
	"identity",
	"sequence",
	"int",
	"integer",
	"varchar",
	"text",
	"boolean",
	"date",
	"timestamp",
	"decimal",
	"float",
	"numeric",
}

var SQLPrefixLit = []string{
}
var SQLPrefixReason = []string{
}

// SQLFinding 表示一条命中。
type SQLFinding struct {
	Reason string
	Detail string
}

// SQLResult 是审计结果。
type SQLResult struct {
	Safe bool
	Findings []SQLFinding
}

func SQLLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func SQLIn(list []string, v string) bool {
	for _, x := range list { if SQLLower(x) == v { return true } }
	return false
}

func SQLSplit(in string) []string {
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

func SQLKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// SQLHas 判定结果是否含某原因。
func SQLHas(r SQLResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// SQLAudit 审计输入字符串。
func SQLAudit(in string) SQLResult {
	res := SQLResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, SQLFinding{Reason: SQLReasonEmpty}); return res }
	toks := SQLSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := SQLLower(tok)
		key := cmp
		switch {
		case SQLIn(SQLBlock, key):
			res.Findings = append(res.Findings, SQLFinding{Reason: SQLReasonBlock, Detail: key})
		case SQLIn(SQLWarn, key):
			res.Findings = append(res.Findings, SQLFinding{Reason: SQLReasonWarn, Detail: key})
		}
		for i, lit := range SQLPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, SQLFinding{Reason: SQLPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
