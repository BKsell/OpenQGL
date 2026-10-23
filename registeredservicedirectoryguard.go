package main

// registeredservicedirectoryguard.go —— 已注册网络服务名风险目录。
//
// 威胁模型：
//   按服务名识别目标端口敏感度（数据库/远程/管理面板/代理/调试），供 SSRF 与本地绑定审计关联端口号。
//   服务名令牌纯字符查表，不发起连接，不用正则。

// RSD 风险类别。
const (
	RSDClassBlock = "block"
	RSDClassWarn  = "warn"
	RSDClassAllow = "allow"
)

const (
	RSDReasonBlock   = "rsd-input-hits-blocked-catalog"
	RSDReasonWarn    = "rsd-input-hits-review-catalog"
	RSDReasonPrefix  = "rsd-input-hits-dangerous-prefix"
	RSDReasonEmpty   = "rsd-input-is-empty"
)

var RSDBlock = []string{
	"mysql",
	"mysqld",
	"postgres",
	"postgresql",
	"pgbouncer",
	"mssql",
	"sqlserver",
	"mongo",
	"mongodb",
	"mongos",
	"redis",
	"redis-cli",
	"memcached",
	"cassandra",
	"couchdb",
	"couchbase",
	"riak",
	"neo4j",
	"influxdb",
	"timescaledb",
	"cockroachdb",
	"clickhouse",
	"elasticsearch",
	"opensearch",
	"solr",
	"kafka",
	"zookeeper",
	"etcd",
	"consul",
	"rabbitmq",
	"amqp",
	"activemq",
	"nats",
	"zeromq",
	"nfs",
	"smbd",
	"smb",
	"cifs",
	"ftp",
	"sftp",
	"tftp",
	"rdp",
	"ms-wbt-server",
	"vnc",
	"ssh",
	"telnet",
	"winrm",
	"wsman",
	"snmp",
	"ldap",
	"ldaps",
	"kerberos",
	"kadmin",
	"docker",
	"dockerd",
	"containerd",
	"kubelet",
	"kube-apiserver",
	"etcd-client",
	"nomad",
	"jenkins",
	"gitlab",
	"nexus",
	"artifactory",
}

var RSDWarn = []string{
	"http",
	"https",
	"www",
	"web",
	"webadmin",
	"admin",
	"manage",
	"management",
	"console",
	"dashboard",
	"grafana",
	"prometheus",
	"kibana",
	"phpmyadmin",
	"adminer",
	"pma",
	"cockpit",
	"portainer",
	"traefik",
	"envoy",
	"nginx",
	"apache",
	"httpd",
	"tomcat",
	"jetty",
	"wildfly",
	"glassfish",
	"websphere",
	"weblogic",
	"jboss",
	"iis",
	"smtp",
	"smtps",
	"submission",
	"imap",
	"imaps",
	"pop3",
	"pop3s",
	"sip",
	"sips",
	"rtsp",
	"rtmps",
	"mqtt",
	"mqtts",
	"stun",
	"turn",
	"isakmp",
	"ipsec",
	"pptp",
	"l2tp",
	"openvpn",
	"wireguard",
	"socks",
	"socks5",
	"proxy",
	"http-proxy",
	"squid",
	"privoxy",
	"tor",
	"x11",
	"x11-forwarding",
	"afp",
	"netbios",
	"netbios-ns",
	"netbios-dgm",
	"netbios-ssn",
	"llmnr",
	"mdns",
	"wsd",
	"upnp",
	"ssdp",
}

var RSDAllow = []string{
	"dns",
	"domain",
	"echo",
	"discard",
	"daytime",
	"chargen",
	"ntp",
	"time",
	"whois",
	"finger",
	"ident",
	"auth",
	"tap",
	"gopher",
	"dict",
	"syslog",
	"lpd",
	"ipp",
	"ipps",
	"printer",
	"ocsp",
	"ocsp-responder",
	"crl",
	"caldav",
	"caldavs",
	"carddav",
	"carddavs",
	"webdav",
	"webdavs",
	"svn",
	"git",
	"hg",
	"fossil",
	"rsync",
	"scp",
	"nis",
	"yp",
}

var RSDPrefixLit = []string{
}
var RSDPrefixReason = []string{
}

// RSDFinding 表示一条命中。
type RSDFinding struct {
	Reason string
	Detail string
}

// RSDResult 是审计结果。
type RSDResult struct {
	Safe bool
	Findings []RSDFinding
}

func RSDLower(x string) string {
	b := []byte(x)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' { b[i] = c + 32 }
	}
	return string(b)
}

func RSDIn(list []string, v string) bool {
	for _, x := range list { if RSDLower(x) == v { return true } }
	return false
}

func RSDSplit(in string) []string {
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

func RSDKeyPart(tok string) string {
	t := tok
	for i := 0; i < len(t); i++ { if t[i] == '=' { t = t[:i]; break } }
	return t
}

// RSDHas 判定结果是否含某原因。
func RSDHas(r RSDResult, reason string) bool {
	for _, f := range r.Findings { if f.Reason == reason { return true } }
	return false
}

// RSDAudit 审计输入字符串。
func RSDAudit(in string) RSDResult {
	res := RSDResult{Safe: true}
	if len(in) == 0 { res.Safe = false; res.Findings = append(res.Findings, RSDFinding{Reason: RSDReasonEmpty}); return res }
	toks := RSDSplit(in)
	for _, raw := range toks {
		tok := raw
		for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') { tok = tok[1:] }
		cmp := RSDLower(tok)
		key := cmp
		switch {
		case RSDIn(RSDBlock, key):
			res.Findings = append(res.Findings, RSDFinding{Reason: RSDReasonBlock, Detail: key})
		case RSDIn(RSDWarn, key):
			res.Findings = append(res.Findings, RSDFinding{Reason: RSDReasonWarn, Detail: key})
		}
		for i, lit := range RSDPrefixLit {
			if len(cmp) >= len(lit) && cmp[:len(lit)] == lit {
				res.Findings = append(res.Findings, RSDFinding{Reason: RSDPrefixReason[i], Detail: lit})
			}
		}
	}
	if len(res.Findings) > 0 { res.Safe = false }
	return res
}
