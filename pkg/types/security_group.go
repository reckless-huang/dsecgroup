package types

import (
	"fmt"
)

// Action 表示安全组规则的动作类型
type Action string

const (
	ActionAllow Action = "allow" // 允许
	ActionDeny  Action = "deny"  // 拒绝
)

// RuleHasher 定义了安全组规则哈希生成的接口
type RuleHasher interface {
	// GenerateRuleHash 根据规则生成哈希值
	GenerateRuleHash(rule SecurityRule) string
	// IsRuleEqual 比较两条规则是否相同
	IsRuleEqual(rule1, rule2 SecurityRule) bool
}

// SecurityRule 表示一条安全组规则
type SecurityRule struct {
	RuleHash    string `json:"rule_hash"`
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Direction   string `json:"direction"`
	Action      Action `json:"action"`
	Priority    int    `json:"priority"`
	Description string `json:"description"`
}

// GetRuleKey 返回用于生成哈希的规则关键信息
func (r *SecurityRule) GetRuleKey() string {
	return fmt.Sprintf("%s:%d:%s:%s:%s", r.IP, r.Port, r.Protocol, r.Direction, r.Action)
}

// SecurityGroup 表示安全组信息
type SecurityGroup struct {
	GroupID     string `json:"group_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	VpcID       string `json:"vpc_id"`
	CreatedAt   string `json:"created_at"`
}

// SecurityGroupConfig 定义云服务商配置
type SecurityGroupConfig struct {
	Provider   string            `json:"provider"`   // 云服务商标识：aliyun, aws, etc
	Region     string            `json:"region"`     // 区域
	Credential map[string]string `json:"credential"` // 认证信息
}

// ProviderFactory 定义了创建 Provider 的工厂接口
type ProviderFactory interface {
	// CreateProvider 根据配置创建对应的云服务商实现
	CreateProvider(config SecurityGroupConfig) (SecurityGroupProvider, error)
}
