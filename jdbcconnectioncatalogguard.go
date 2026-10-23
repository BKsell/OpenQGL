package main

// jdbcconnectioncatalogguard.go —— JDBC 连接串风险目录。
//
// 威胁模型：
//   JDBC URL 可经 autoDeserialize/queryInterceptors/allowLoadLocalInfile/Factory 触发 RCE 或读本地文件。
//   本目录收录危险 JDBC 前缀与属性键，纯字符查表，不建连，不用正则。

const (
	JDCClassBlock   = "block"
	JDCClassWarn    = "warn"
	JDCClassAllow   = "allow"
	JDCClassUnknown = "unknown"
)

var JDCBlock = []string{
	"autoDeserialize",
	"queryInterceptors",
	"statementInterceptors",
	"exceptionInterceptors",
	"allowLoadLocalInfile",
	"allowUrlInLocalInfile",
	"allowLoadLocalInfileInPath",
	"detectCustomCollations",
	"allowMultiQueries",
	"allowPublicKeyRetrieval",
	"useServerPrepStmts",
	"jdbc:mysql:",
	"jdbc:mariadb:",
	"jdbc:postgresql:",
	"jdbc:oracle:",
	"jdbc:sqlserver:",
	"jdbc:jtds:",
	"jdbc:db2:",
	"jdbc:sqlite:",
	"jdbc:h2:",
	"jdbc:hsqldb:",
	"jdbc:derby:",
	"jdbc:sybase:",
	"jdbc:informix:",
	"jdbc:clickhouse:",
	"jdbc:snowflake:",
	"jdbc:hive2:",
	"jdbc:presto:",
	"jdbc:trino:",
	"jdbc:log4jdbc:",
	"jdbc:tc:",
	"jdbc:shardingsphere:",
	"jdbc:kingbase8:",
	"jdbc:dm:",
	"jdbc:gbase:",
	"jdbc:oscar:",
	"jdbc:vertica:",
	"jdbc:postgresql:replication",
	"jdbc:fake:",
	"jdbc:config:",
	"jdbc:xml:",
	"jdbc:jar:",
	"jdbc:war:",
	"jdbc:zip:",
	"jdbc:file:",
	"jdbc:http:",
	"jdbc:https:",
	"jdbc:netdoc:",
	"jdbc:jar:http",
	"jdbc:rmi:",
	"jdbc:ldap:",
	"jdbc:dns:",
	"jdbc:logging:",
	"jdbc:sqlserver:integratedSecurity",
	"jdbc:sqlserver:authentication",
}

var JDCWarn = []string{
	"jdbc:",
	"connectionString",
	"connectionURL",
	"datasource",
	"DataSource",
	"DriverManager",
	"getConnection",
	"socketFactory",
	"socketFactoryClass",
	"sslMode",
	"useSSL",
	"requireSSL",
	"verifyServerCertificate",
	"trustServerCertificate",
	"trustStore",
	"serverTimezone",
	"characterEncoding",
	"createDatabaseIfNotExist",
	"tinyInt1isBit",
	"useTimezone",
	"zeroDateTimeBehavior",
}

var JDCAllow = []string{
	"com.mysql.cj.jdbc.Driver",
	"org.postgresql.Driver",
	"oracle.jdbc.OracleDriver",
	"com.microsoft.sqlserver.jdbc.SQLServerDriver",
	"org.mariadb.jdbc.Driver",
	"org.sqlite.JDBC",
	"org.h2.Driver",
}

func JDCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func JDCIn(list []string, v string) bool {
	for _, x := range list { if JDCLower(x) == v { return true } }
	return false
}

// JDCClassify 分类单个令牌。
func JDCClassify(tok string) string {
	v := JDCLower(tok)
	switch {
	case JDCIn(JDCBlock, v): return JDCClassBlock
	case JDCIn(JDCWarn, v): return JDCClassWarn
	case JDCIn(JDCAllow, v): return JDCClassAllow
	default: return JDCClassUnknown
	}
}
