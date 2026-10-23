package main

// cloudapiscopecatalogguard.go —— 云 API 高权限 scope 目录。
//
// 威胁模型：
//   iam:/admin/fullaccess/ListAllMyBuckets/iam:PassRole/DelegationAdmin 等 scope 过宽应最小化。纯字符查表，不用正则。

const (
	CASClassBlock   = "block"
	CASClassWarn    = "warn"
	CASClassAllow   = "allow"
	CASClassUnknown = "unknown"
)

var CASBlock = []string{
	"AdministratorAccess",
	"FullAccess",
	"iam:PassRole",
	"iam:CreateRole",
	"iam:AttachRolePolicy",
	"iam:PutRolePolicy",
	"iam:AssumeRole",
	"sts:AssumeRole",
	"organizations:*",
	"*",
	"iam:*",
	"root",
	"s3:DeleteBucket",
	"s3:PutBucketPolicy",
	"s3:PutBucketAcl",
	"iam:AddUserToGroup",
	"iam:CreateAccessKey",
	"iam:CreateLoginProfile",
	"cloudtrail:StopLogging",
	"guardduty:Disassociate",
}

var CASWarn = []string{
	"s3:ListAllMyBuckets",
	"s3:GetObject",
	"s3:PutObject",
	"ec2:RunInstances",
	"ec2:AssociateIamInstanceProfile",
	"iam:ListRoles",
	"iam:GetRole",
	"sts:GetCallerIdentity",
	"iam:ListAccessKeys",
	"s3:ListBucket",
	"ec2:DescribeInstances",
	"lambda:CreateFunction",
	"lambda:InvokeFunction",
	"secretsmanager:GetSecretValue",
	"kms:Decrypt",
	"organizations:DescribeOrganization",
}

var CASAllow = []string{
	"sts:DecodeAuthorizationMessage",
	"iam:GetUser",
	"s3:HeadBucket",
	"s3:GetBucketLocation",
	"ec2:DescribeRegions",
	"iam:GetAccountPasswordPolicy",
	"iam:ListAccountAliases",
	"s3:GetObjectVersion",
}

func CASLower(x string) string {
	b := []byte(x)
	for i, c := range b { if c >= 'A' && c <= 'Z' { b[i] = c + 32 } }
	return string(b)
}

func CASIn(list []string, v string) bool {
	for _, x := range list { if CASLower(x) == v { return true } }
	return false
}

// CASClassify 分类单个令牌。
func CASClassify(tok string) string {
	v := CASLower(tok)
	switch {
	case CASIn(CASBlock, v): return CASClassBlock
	case CASIn(CASWarn, v): return CASClassWarn
	case CASIn(CASAllow, v): return CASClassAllow
	default: return CASClassUnknown
	}
}
