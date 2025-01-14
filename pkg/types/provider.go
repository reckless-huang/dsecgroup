package types

// Region 表示地域信息
type Region struct {
	RegionID  string `json:"region_id"`
	LocalName string `json:"local_name"`
}

// CloudProvider 定义云服务商的基础操作接口
type CloudProvider interface {
	// ListRegions 获取可用地域列表
	ListRegions() ([]Region, error)
}

// SecurityGroupProvider 继承 CloudProvider 接口
type SecurityGroupProvider interface {
	CloudProvider

	// 安全组基本信息操作
	ListSecurityGroups() ([]SecurityGroup, error)
	GetSecurityGroup(groupID string) (*SecurityGroup, error)
	CreateSecurityGroup(name, description string) (*SecurityGroup, error)
	DeleteSecurityGroup(groupID string) error

	// 安全组规则操作
	AddRule(groupID string, rule SecurityRule) error
	RemoveRule(groupID string, rule SecurityRule) error
	UpdateRule(groupID string, ruleID string, rule SecurityRule) error
	GetRule(groupID string, ruleID string) (*SecurityRule, error)
	ListRules(groupID string) ([]SecurityRule, error)
}
