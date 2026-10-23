package main

// nosqloperatorcatalogguard.go —— NoSQL 注入操作符目录。
//
// 威胁模型：
//   Mongo/类 NoSQL 查询里 $ne/$gt/$where/$regex/$expr 等操作符来自输入即可绕过校验或注入 JS。纯字符查表，不用正则。

const (
	NQLClassBlock   = "block"
	NQLClassWarn    = "warn"
	NQLClassAllow   = "allow"
	NQLClassUnknown = "unknown"
)

var NQLBlock = []string{
	"$where",
	"$function",
	"$accumulator",
	"$comment",
	"$regex",
	"$options",
	"$expr",
	"$functionNow",
	"$functionSleep",
	"$gt",
	"$gte",
	"$lt",
	"$lte",
	"$ne",
	"$eq",
	"$nin",
	"$in",
	"$exists",
	"$type",
	"$size",
	"$mod",
	"$all",
	"$nor",
	"$or",
	"$and",
	"$not",
	"$elemMatch",
	"$near",
	"$within",
	"$geoNear",
	"$center",
	"$polygon",
	"$where-this",
}

var NQLWarn = []string{
	"$set",
	"$unset",
	"$inc",
	"$push",
	"$pull",
	"$addToSet",
	"$rename",
	"$bit",
	"$currentDate",
	"$min",
	"$max",
	"$mul",
	"$pop",
	"$each",
	"$slice",
	"$sort",
	"$limit",
	"$lookup",
	"$graphLookup",
	"$mapReduce",
	"$out",
	"$merge",
}

var NQLAllow = []string{
	"find",
	"findOne",
	"aggregate",
	"count",
	"distinct",
	"project",
	"match",
	"group",
	"sum",
	"avg",
	"unwind",
	"index",
	"collation",
	"hint",
	"batchSize",
}

func NQLLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func NQLIn(list []string, v string) bool {
	for _, x := range list { if NQLLower(x) == v { return true } }
	return false
}

// NQLClassify 分类单个令牌。
func NQLClassify(tok string) string {
	v := NQLLower(tok)
	switch {
	case NQLIn(NQLBlock, v): return NQLClassBlock
	case NQLIn(NQLWarn, v): return NQLClassWarn
	case NQLIn(NQLAllow, v): return NQLClassAllow
	default: return NQLClassUnknown
	}
}
