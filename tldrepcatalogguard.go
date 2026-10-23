package main

// tldrepcatalogguard.go —— 顶级域/后缀信誉目录与域名风险判定守卫。
//
// 背景：
//   启动器会从第三方拉取服务器列表、更新清单、皮肤站、短链跳转。大量免费/宽松/低价 TLD 与新 gTLD
//   被滥用于钓鱼、C2、malvertising；IDN 同形 + 高风险后缀放大钓鱼成功率。本模块：
//     - 维护 ccTLD / gTLD / 高风险后缀目录（逐条列举，便于审计，不使用正则）；
//     - 提供纯判定：取最后一个标签比对后缀目录、标注风险等级、识别裸 IP 当域名；
//     - 多级后缀（co.uk 类）不在本模块展开，交由 PSL 专用模块，本模块只判最后标签。
//   纯字符串判定，不做任何 DNS 请求。

// TDC 后缀风险等级。
const (
	TDCRiskLow    = "low"    // 常见主流后缀，注册门槛/滥用管理相对成熟
	TDCRiskMedium = "medium" // 一般 gTLD
	TDCRiskHigh   = "high"   // 历史滥用率高/极低价/免费/宽松审核后缀
)

// TDC 原因码。
const (
	TDCReasonUnknownSuffix   = "domain-uses-unrecognized-tld"
	TDCReasonHighRiskSuffix  = "domain-uses-high-risk-tld"
	TDCReasonIPAsDomain      = "host-is-literal-ip-not-domain-name"
	TDCReasonEmptyHost       = "host-is-empty"
	TDCReasonTrailingDot     = "host-has-trailing-dot-fqdn-marker"
	TDCReasonLeadingDot      = "host-has-leading-dot"
	TDCReasonEmptyLabel      = "domain-contains-empty-label"
	TDCReasonLabelTooLong    = "domain-label-exceeds-63-characters"
	TDCReasonNameTooLong     = "domain-exceeds-253-characters"
	TDCReasonBadLabelChar    = "domain-label-contains-illegal-character"
	TDCReasonLabelHyphenEdge = "domain-label-starts-or-ends-with-hyphen"
	TDCReasonNumericTld      = "tld-label-is-purely-numeric"
)

// TDCHighRiskTLDs 历史滥用率高/低价/免费/宽松的后缀（不含前导点，小写）。
var TDCHighRiskTLDs = []string{
	"xyz", "top", "click", "country", "stream", "download", "loan", "men",
	"party", "review", "trade", "win", "accountant", "cricket", "science",
	"faith", "webcam", "bid", "racing", "date", "win", "gq", "tk", "ml",
	"ga", "cf", "work", "fit", "info", "biz", "ru", "su", "cn", "kp",
	"zw", "zip", "mov", "review", "country", "kim", "science", "cricket",
	"party", "trade", "racing", "bid", "win", "download", "stream", "click",
	"loan", "men", "date", "faith", "webcam", "accountant", "gdn", "rest",
	"cyou", "sbs", "bd", "monster", "icu", "link", "work", "shop", "club",
	"online", "site", "fun", "live", "tech", "space", "website", "pw",
	"su", "to", "ga", "ml", "cf", "tk", "gq", "000webhostapp",
	"zyrosite", "wixsite", "weebly", "blogspot", "github-io",
}

// TDCCcTLDs ISO 3166-1 国家/地区代码顶级域（小写）。
var TDCCcTLDs = []string{
	"ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar",
	"as", "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf",
	"bg", "bh", "bi", "bj", "bl", "bm", "bn", "bo", "bq", "br", "bs",
	"bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch",
	"ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cw", "cx",
	"cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "ee", "eg",
	"eh", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr",
	"ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn",
	"gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn",
	"hr", "ht", "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir",
	"is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km",
	"kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk",
	"lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mf",
	"mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms",
	"mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne", "nf",
	"ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe",
	"pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw",
	"py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd",
	"se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr",
	"ss", "st", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th",
	"tj", "tk", "tl", "tm", "tn", "to", "tp", "tr", "tt", "tv", "tw",
	"tz", "ua", "ug", "uk", "um", "us", "uy", "uz", "va", "vc", "ve",
	"vg", "vi", "vn", "vu", "wf", "ws", "ye", "yt", "za", "zm", "zw",
}

// TDCGtlds 常规/新通用顶级域（小写，列举主流集合）。
var TDCGtlds = []string{
	"com", "org", "net", "edu", "gov", "mil", "int", "aero", "asia",
	"biz", "coop", "info", "museum", "name", "post", "pro", "tel",
	"travel", "xxx", "mobi", "jobs", "cat", "academy", "accountant",
	"accountants", "actor", "adult", "africa", "agency", "airforce",
	"apartments", "app", "apple", "archi", "army", "art", "associates",
	"attorney", "auction", "auto", "baby", "band", "bank", "bar",
	"bargains", "baseball", "basketball", "beauty", "beer", "best",
	"bet", "bible", "bid", "bike", "bingo", "bio", "black", "blog",
	"blue", "boats", "book", "boots", "boutique", "box", "broker",
	"build", "builders", "business", "buy", "cab", "cafe", "cam",
	"camera", "camp", "capital", "car", "cards", "care", "career",
	"careers", "cars", "case", "cash", "casino", "catering", "center",
	"ceo", "cern", "chain", "chair", "charity", "chat", "cheap",
	"church", "city", "claims", "cleaning", "click", "clinic", "clothing",
	"cloud", "club", "coach", "codes", "coffee", "college", "cologne",
	"community", "company", "compare", "computer", "condos", "construction",
	"consulting", "contact", "contractors", "cooking", "cool", "country",
	"coupons", "courses", "credit", "creditcard", "cricket", "cruises",
	"cyou", "dance", "data", "date", "dating", "day", "deals", "degree",
	"delivery", "democrat", "dental", "dentist", "department", "design",
	"dev", "diamonds", "diet", "digital", "direct", "directory", "discount",
	"doctor", "dog", "domains", "download", "drive", "earth", "eat",
	"education", "email", "energy", "engineer", "engineering", "enterprises",
	"equipment", "estate", "events", "exchange", "expert", "exposed",
	"express", "fail", "faith", "family", "fan", "fans", "farm", "fashion",
	"fast", "feedback", "fiat", "film", "final", "finance", "financial",
	"fire", "fish", "fishing", "fit", "fitness", "flights", "florist",
	"flowers", "fly", "foo", "food", "football", "forex", "forsale",
	"forum", "foundation", "free", "fun", "fund", "furniture", "fyi",
	"gallery", "game", "games", "garden", "gay", "gift", "gifts", "gives",
	"glass", "global", "globo", "gmail", "gold", "golf", "gop", "graphics",
	"gratis", "green", "gripe", "grocery", "group", "guide", "guitars",
	"guru", "hair", "haus", "health", "healthcare", "help", "here", "hiphop",
	"hockey", "holdings", "holiday", "home", "homes", "horse", "hospital",
	"host", "hosting", "hot", "hotel", "house", "how", "ice", "inc",
	"industries", "info", "ink", "institute", "insurance", "insure",
	"international", "investments", "irish", "jewelry", "jobs", "joy",
	"kim", "kitchen", "kiwi", "land", "lat", "law", "lawyer", "lease",
	"leclerc", "legal", "lgbt", "life", "lighting", "limited", "limo",
	"link", "live", "llc", "loan", "loans", "lol", "london", "love",
	"ltd", "luxe", "luxury", "maison", "makeup", "management", "map",
	"market", "marketing", "markets", "mba", "media", "memorial", "men",
	"menu", "miami", "mil", "mini", "mint", "mobile", "moda", "mom",
	"money", "monster", "mortgage", "motorcycles", "mov", "music", "navy",
	"network", "new", "news", "ngo", "ninja", "now", "observer", "one",
	"online", "onyourside", "org", "organic", "page", "panerai", "paris",
	"partners", "parts", "party", "pay", "pet", "phd", "phone", "photo",
	"photography", "photos", "physio", "pics", "pictures", "pid", "pin",
	"pink", "pizza", "place", "planet", "plastic", "play", "players",
	"plus", "poker", "porn", "press", "prime", "productions", "prof",
	"promo", "properties", "property", "protection", "pub", "quest",
	"racing", "radio", "realty", "red", "rent", "rentals", "repair",
	"report", "republican", "rest", "restaurant", "review", "reviews",
	"rich", "rip", "rocks", "rodeo", "room", "rugby", "run", "sale",
	"salon", "save", "school", "science", "secure", "security", "select",
	"services", "sex", "sexy", "shoes", "shop", "shopping", "show",
	"singles", "site", "ski", "skin", "social", "software", "solar",
	"solutions", "song", "space", "spot", "sport", "sports", "spot",
	"srl", "storage", "store", "stream", "studio", "study", "style",
	"sucks", "supplies", "supply", "support", "surf", "surgery", "sustainable",
	"swiss", "sympathy", "systems", "tax", "taxi", "team", "tech",
	"technology", "tennis", "theater", "theatre", "tickets", "tips",
	"tires", "today", "tools", "top", "tours", "town", "toys", "trade",
	"trading", "training", "travel", "tube", "university", "uno",
	"vacations", "vegas", "ventures", "vet", "viajes", "video", "villas",
	"vin", "vip", "vision", "vlaanderen", "vodka", "vote", "voting",
	"voyage", "wales", "watch", "watches", "weather", "webcam", "website",
	"wed", "wedding", "whoswho", "wiki", "win", "wine", "winners",
	"work", "works", "world", "wow", "xyz", "yachts", "yoga", "zone",
}

// TDCFinding 表示一个域名/后缀问题。
type TDCFinding struct {
	Reason string
	Detail string
}

// TDCResult 是域名判定结果。
type TDCResult struct {
	Safe     bool
	TLD      string
	Risk     string
	Findings []TDCFinding
}

func tdInList(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// TDCTldRisk 返回后缀的风险等级，未收录返回空串。
func TDCTldRisk(tld string) string {
	t := FTCLower(tld)
	if tdInList(TDCHighRiskTLDs, t) {
		return TDCRiskHigh
	}
	if tdInList(TDCCcTLDs, t) {
		return TDCRiskMedium
	}
	if tdInList(TDCGtlds, t) {
		return TDCRiskLow
	}
	return ""
}

// TDCIsNumericLabel 判定标签是否纯数字。
func TDCIsNumericLabel(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// TDCLastLabel 返回小写最后一个标签。
func TDCLastLabel(host string) string {
	h := host
	for len(h) > 0 && h[len(h)-1] == '.' {
		h = h[:len(h)-1]
	}
	dot := -1
	for i := 0; i < len(h); i++ {
		if h[i] == '.' {
			dot = i
		}
	}
	if dot < 0 {
		return FTCLower(h)
	}
	return FTCLower(h[dot+1:])
}

// TDCAuditHost 审计主机名（不含端口/路径，调用方应先剥离）。
func TDCAuditHost(host string) TDCResult {
	res := TDCResult{Safe: true, Risk: TDCRiskLow}
	h := host
	if h == "" {
		res.Safe = false
		res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonEmptyHost})
		return res
	}
	if h[0] == '.' {
		res.Safe = false
		res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonLeadingDot})
	}
	if h[len(h)-1] == '.' {
		res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonTrailingDot})
		h = h[:len(h)-1]
	}
	if len(h) > 253 {
		res.Safe = false
		res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonNameTooLong})
	}
	// 单标签纯数字 / 整体像 IPv4：裸 IP 当域名使用。
	labels := TDCSplitLabels(h)
	if len(labels) == 4 && TDCLabelsAllNumeric(labels) {
		res.Safe = false
		res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonIPAsDomain, Detail: h})
		return res
	}
	for _, lab := range labels {
		if lab == "" {
			res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonEmptyLabel})
			continue
		}
		if len(lab) > 63 {
			res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonLabelTooLong, Detail: lab})
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonLabelHyphenEdge, Detail: lab})
		}
		for i := 0; i < len(lab); i++ {
			c := lab[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonBadLabelChar, Detail: lab})
				break
			}
		}
	}
	if len(labels) > 0 {
		tld := FTCLower(labels[len(labels)-1])
		res.TLD = tld
		if TDCIsNumericLabel(tld) {
			res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonNumericTld})
		} else {
			risk := TDCTldRisk(tld)
			res.Risk = risk
			if risk == "" {
				res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonUnknownSuffix, Detail: tld})
			} else if risk == TDCRiskHigh {
				res.Findings = append(res.Findings, TDCFinding{Reason: TDCReasonHighRiskSuffix, Detail: tld})
			}
		}
	}
	if len(res.Findings) > 0 {
		res.Safe = false
	}
	return res
}

// TDCSplitLabels 按点切分主机名。
func TDCSplitLabels(h string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(h); i++ {
		if i == len(h) || h[i] == '.' {
			out = append(out, h[start:i])
			start = i + 1
		}
	}
	return out
}

// TDCLabelsAllNumeric 判定标签集合是否全部为数字（IPv4 形态）。
func TDCLabelsAllNumeric(labels []string) bool {
	if len(labels) == 0 {
		return false
	}
	for _, l := range labels {
		if !TDCIsNumericLabel(l) {
			return false
		}
	}
	return true
}

// TDCHas 判定是否含某原因。
func TDCHas(r TDCResult, reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
