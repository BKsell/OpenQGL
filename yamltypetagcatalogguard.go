package main

// yamltypetagcatalogguard.go —— YAML/序列化类型标签目录。
//
// 威胁模型：
//   SnakeYAML/Jackson/YAML 的 !!type 标签可实例化任意类（javax.script.ScriptEngineManager 等）。
//   本目录收录危险类型标签，纯字符查表，不用正则。

const (
	YTTClassBlock   = "block"
	YTTClassWarn    = "warn"
	YTTClassAllow   = "allow"
	YTTClassUnknown = "unknown"
)

var YTTBlock = []string{
	"!!javax.script.ScriptEngineManager",
	"!!javax.script.ScriptEngine",
	"!!java.lang.Runtime",
	"!!java.lang.ProcessBuilder",
	"!!java.lang.Process",
	"!!java.lang.ProcessImpl",
	"!!javax.naming.InitialContext",
	"!!javax.management.remote.rmi.RMIConnector",
	"!!com.sun.rowset.JdbcRowSetImpl",
	"!!org.springframework.context.support.ClassPathXmlApplicationContext",
	"!!org.springframework.context.support.FileSystemXmlApplicationContext",
	"!!org.apache.commons.beanutils.BeanComparator",
	"!!org.apache.commons.collections.functors.InvokerTransformer",
	"!!org.apache.commons.collections4.functors.InvokerTransformer",
	"!!com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
	"!!java.util.ServiceLoader",
	"!!java.beans.EventHandler",
	"!!java.lang.reflect.Proxy",
	"!!org.codehaus.groovy.runtime.MethodClosure",
	"!!groovy.util.Expando",
	"!!bsh.Interpreter",
	"!!bsh.XThis",
	"!!com.mchange.v2.c3p0.JndiRefForwardingDataSource",
	"!!org.yaml.snakeyaml.Yaml",
	"!!com.alibaba.fastjson.JSONObject",
	"!!javax.activation.URLDataSource",
	"!!java.net.URL",
	"!!java.net.URLClassLoader",
	"!!java.io.FileOutputStream",
	"!!java.io.FileInputStream",
	"!!org.apache.commons.io.input.XmlStreamReader",
	"!!com.thoughtworks.xstream.XStream",
	"!!org.codehaus.jackson.map.ObjectMapper",
	"!!org.hibernate.property.BasicPropertyAccessor",
	"!!org.apache.commons.configuration.JNDIConfiguration",
	"!!org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS",
	"!!org.apache.tomcat.dbcp.dbcp2.cpdsadapter.DriverAdapterCPDS",
	"!!org.apache.click.control.Column",
	"!!net.sf.json.JSONObject",
	"!!javassist.tools.rmi.ObjectNotFoundException",
	"!!org.mozilla.javascript.NativeJavaObject",
	"!!org.codehaus.groovy.runtime.ConvertedClosure",
	"!!com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter",
	"!!org.springframework.jndi.support.SimpleJndiBeanFactory",
	"!!org.springframework.transaction.jta.JtaTransactionManager",
}

var YTTWarn = []string{
	"!!java.util.HashMap",
	"!!java.util.LinkedHashMap",
	"!!java.util.TreeMap",
	"!!java.util.HashSet",
	"!!java.util.LinkedHashSet",
	"!!java.util.TreeSet",
	"!!java.util.ArrayList",
	"!!java.util.LinkedList",
	"!!java.util.Date",
	"!!java.sql.Timestamp",
	"!!java.math.BigDecimal",
	"!!java.math.BigInteger",
	"!!java.lang.Object",
	"!!java.lang.Class",
	"!!java.lang.ClassLoader",
	"!!java.lang.Thread",
	"!!java.lang.Exception",
	"!!java.lang.RuntimeException",
	"!!org.yaml.snakeyaml.constructor.Constructor",
	"!!org.yaml.snakeyaml.constructor.SafeConstructor",
	"tag:yaml.org,2002:",
	"!!str",
	"!!int",
	"!!float",
	"!!bool",
	"!!binary",
	"!!timestamp",
	"!!omap",
	"!!pairs",
	"!!set",
	"!!seq",
	"!!map",
	"!!null",
	"!!python/object",
	"!!python/module",
	"!!ruby/object",
	"!!php/object",
	"!!js/function",
	"!!perl/object",
}

var YTTAllow = []string{
	"safe",
	"SafeConstructor",
	"literal",
	"plain",
	"scalar",
	"mapping",
	"sequence",
	"document",
}

func YTTLower(x string) string {
	return x
}

func YTTIn(list []string, v string) bool {
	for _, x := range list { if YTTLower(x) == v { return true } }
	return false
}

// YTTClassify 分类单个令牌。
func YTTClassify(tok string) string {
	v := YTTLower(tok)
	switch {
	case YTTIn(YTTBlock, v): return YTTClassBlock
	case YTTIn(YTTWarn, v): return YTTClassWarn
	case YTTIn(YTTAllow, v): return YTTClassAllow
	default: return YTTClassUnknown
	}
}
