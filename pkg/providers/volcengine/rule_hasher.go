package volcengine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/reckless-huang/dsecgroup/pkg/types"
)

// RuleHasher 实现规则哈希生成器
type RuleHasher struct{}

// GenerateRuleHash 根据规则生成哈希值
func (h *RuleHasher) GenerateRuleHash(rule types.SecurityRule) string {
	key := fmt.Sprintf("%s:%d:%s:%s:%s",
		rule.IP,
		rule.Port,
		rule.Protocol,
		rule.Direction,
		rule.Action,
	)

	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// IsRuleEqual 比较两条规则是否相同
func (h *RuleHasher) IsRuleEqual(rule1, rule2 types.SecurityRule) bool {
	return rule1.IP == rule2.IP &&
		rule1.Port == rule2.Port &&
		rule1.Protocol == rule2.Protocol &&
		rule1.Direction == rule2.Direction &&
		rule1.Action == rule2.Action
}
