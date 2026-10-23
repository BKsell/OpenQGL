package main

// desergadgetcatalogguard.go —— Java 反序列化 Gadget 目录。
//
// 威胁模型：
//   Java 原生/XML/YAML 反序列化输入中出现已知 gadget 链的触发器类（InvokerTransformer、BeanComparator、
//   TemplatesImpl、JdbcRowSetImpl 等）即应阻断。类名同时收录 / 与 . 形式，纯字符查表，不用正则。

const (
	DGCClassBlock   = "block"
	DGCClassWarn    = "warn"
	DGCClassAllow   = "allow"
	DGCClassUnknown = "unknown"
)

var DGCBlock = []string{
	"org.apache.commons.collections.functors.InvokerTransformer",
	"org.apache.commons.collections4.functors.InvokerTransformer",
	"org.apache.commons.collections.functors.ChainedTransformer",
	"org.apache.commons.collections4.functors.ChainedTransformer",
	"org/apache/commons/collections/functors/InvokerTransformer",
	"org/apache/commons/collections4/functors/InvokerTransformer",
	"org.apache.commons.beanutils.BeanComparator",
	"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
	"com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter",
	"com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl",
	"com.sun.org.apache.xalan.internal.xsltc.DOM",
	"com.sun.rowset.JdbcRowSetImpl",
	"com.sun.org.apache.bcel.internal.util.ClassLoader",
	"org.apache.commons.collections.keyvalue.TiedMapEntry",
	"org.apache.commons.collections4.keyvalue.TiedMapEntry",
	"org.apache.commons.collections.map.LazyMap",
	"org.apache.commons.collections4.map.LazyMap",
	"org.apache.commons.collections.functors.ConstantTransformer",
	"org.apache.commons.collections4.functors.ConstantTransformer",
	"org.apache.commons.collections.functors.ClosureTransformer",
	"org.apache.commons.collections4.functors.ClosureTransformer",
	"org.springframework.beans.factory.ObjectFactory",
	"org.springframework.jndi.support.SimpleJndiBeanFactory",
	"org.springframework.transaction.jta.JtaTransactionManager",
	"com.mchange.v2.c3p0.JndiRefForwardingDataSource",
	"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
	"com.mchange.v2.c3p0.PoolBackedDataSource",
	"com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",
	"org.codehaus.groovy.runtime.ConvertedClosure",
	"org.codehaus.groovy.runtime.MethodClosure",
	"groovy.util.Expando",
	"org.codehaus.groovy.runtime.InvokerHelper",
	"bsh.XThis",
	"bsh.Interpreter",
	"javax.script.ScriptEngineManager",
	"com.sun.script.javascript.RhinoScriptEngine",
	"org.mozilla.javascript.NativeJavaObject",
	"org.mozilla.javascript.MemberBox",
	"org.mozilla.javascript.DefiningClassLoader",
	"javassist.util.proxy.AbstractTranslet",
	"javassist.ClassPool",
	"net.sf.json.JSONObject",
	"net.sf.json.util.JSONUtils",
	"org.hibernate.engine.spi.TypedValue",
	"org.hibernate.tuple.component.AbstractComponentTuplizer",
	"org.hibernate.property.access.spi.Getter",
	"org.hibernate.property.BasicPropertyAccessor",
	"org.apache.click.control.Column",
	"org.apache.commons.dbcp.datasources.SharedPoolDataSource",
	"org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS",
	"org.apache.tomcat.dbcp.dbcp.datasources.SharedPoolDataSource",
	"org.apache.tomcat.dbcp.dbcp2.cpdsadapter.DriverAdapterCPDS",
	"com.alibaba.fastjson.JSONObject",
	"com.alibaba.fastjson.JSON",
	"com.alibaba.fastjson.JSONArray",
	"org.codehaus.jackson.map.ObjectMapper",
	"org.apache.commons.configuration.JNDIConfiguration",
	"javax.management.BadAttributeValueExpException",
	"java.lang.Runtime",
	"java.lang.ProcessBuilder",
	"java.lang.Process",
	"javax.naming.InitialContext",
	"javax.naming.Context",
	"java.lang.reflect.Proxy",
	"java.beans.EventHandler",
	"java.util.ServiceLoader",
	"org.yaml.snakeyaml.Yaml",
	"com.thoughtworks.xstream.XStream",
}

var DGCWarn = []string{
	"java.io.ObjectInputStream",
	"java.io.ObjectOutputStream",
	"java.io.Serializable",
	"java.io.Externalizable",
	"readObject",
	"readResolve",
	"readExternal",
	"writeObject",
	"writeReplace",
	"validateObject",
	"ObjectInputFilter",
	"serialPersistentFields",
	"serialVersionUID",
	"resolveClass",
	"resolveProxyClass",
	"lookup",
	"Jndi",
	"JNDI",
	"ldap",
	"rmi",
	"InitialDirContext",
	"Class.forName",
	"defineClass",
	"URLClassLoader",
	"newInstance",
	"forName",
}

var DGCAllow = []string{
	"java.lang.String",
	"java.lang.Integer",
	"java.lang.Long",
	"java.lang.Boolean",
	"java.lang.Double",
	"java.lang.Float",
	"java.lang.Number",
	"java.util.ArrayList",
	"java.util.HashMap",
	"java.util.HashSet",
	"java.util.LinkedList",
	"java.time.Instant",
	"java.time.LocalDate",
	"java.util.UUID",
	"java.math.BigDecimal",
	"java.math.BigInteger",
}

func DGCLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func DGCIn(list []string, v string) bool {
	for _, x := range list { if DGCLower(x) == v { return true } }
	return false
}

// DGCClassify 分类单个令牌。
func DGCClassify(tok string) string {
	v := DGCLower(tok)
	switch {
	case DGCIn(DGCBlock, v): return DGCClassBlock
	case DGCIn(DGCWarn, v): return DGCClassWarn
	case DGCIn(DGCAllow, v): return DGCClassAllow
	default: return DGCClassUnknown
	}
}
