package aliyun

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"

	"github.com/reckless-huang/dsecgroup/pkg/types"
)

// RuleHasher 阿里云规则哈希生成器
type RuleHasher struct{}

// GenerateRuleHash 生成阿里云规则哈希
func (h *RuleHasher) GenerateRuleHash(rule types.SecurityRule) string {
	// 阿里云特殊处理：端口为 -1 时表示所有端口
	port := rule.Port
	if port == -1 {
		port = 1 // 阿里云使用 1/65535 表示所有端口
	}

	key := fmt.Sprintf("%s:%d:%s:%s:%s",
		rule.IP,
		port,
		rule.Protocol,
		rule.Direction,
		rule.Action,
	)

	hash := sha1.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

// IsRuleEqual 比较两条规则是否相同
func (h *RuleHasher) IsRuleEqual(rule1, rule2 types.SecurityRule) bool {
	// 阿里云特殊处理：比较时考虑端口的特殊情况
	port1 := rule1.Port
	port2 := rule2.Port
	if port1 == -1 {
		port1 = 1
	}
	if port2 == -1 {
		port2 = 1
	}

	return rule1.IP == rule2.IP &&
		port1 == port2 &&
		rule1.Protocol == rule2.Protocol &&
		rule1.Direction == rule2.Direction &&
		rule1.Action == rule2.Action
}
