package volcengine

import (
	"fmt"
	"log/slog"

	"github.com/reckless-huang/dsecgroup/pkg/types"
	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

type Provider struct {
	client *ecs.ECS
	region string
	types.RuleHasher
}

// NewProvider 创建火山云提供商实例
func NewProvider(config types.SecurityGroupConfig) (*Provider, error) {
	accessKey := config.Credential["access_key_id"]
	secretKey := config.Credential["access_key_secret"]
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("access_key_id and access_key_secret are required")
	}
	slog.Debug("accessKey", accessKey)
	slog.Debug("secretKey", secretKey)
	// 设置默认地域为cn-beijing
	region := "cn-beijing"
	if config.Region != "" {
		region = config.Region
	}

	cfg := volcengine.NewConfig().
		WithRegion(region).
		WithCredentials(credentials.NewStaticCredentials(accessKey, secretKey, ""))

	sess, err := session.NewSession(cfg)
	if err != nil {
		return nil, fmt.Errorf("create volcengine session failed: %v", err)
	}

	client := ecs.New(sess)
	if client == nil {
		return nil, fmt.Errorf("create volcengine client failed")
	}

	return &Provider{
		client: client,
		region: config.Region,
	}, nil
}

// ListRegions 获取可用地域列表
func (p *Provider) ListRegions() ([]types.Region, error) {
	request := &ecs.DescribeRegionsInput{}
	response, err := p.client.DescribeRegions(request)
	if err != nil {
		return nil, fmt.Errorf("list regions failed: %v", err)
	}

	regions := make([]types.Region, 0)
	for _, r := range response.Regions {
		regions = append(regions, types.Region{
			RegionID:  *r.RegionId,
			LocalName: *r.RegionId, // 火山云API没有提供本地名称，使用RegionId代替
		})
	}

	return regions, nil
}

// ListSecurityGroups 获取安全组列表
func (p *Provider) ListSecurityGroups() ([]types.SecurityGroup, error) {
	panic("not implemented")
}

// GetSecurityGroup 获取安全组详情
func (p *Provider) GetSecurityGroup(groupID string) (*types.SecurityGroup, error) {
	panic("not implemented")
}

// CreateSecurityGroup 创建安全组
func (p *Provider) CreateSecurityGroup(name, description string) (*types.SecurityGroup, error) {
	panic("not implemented")
}

// DeleteSecurityGroup 删除安全组
func (p *Provider) DeleteSecurityGroup(groupID string) error {
	panic("not implemented")
}

// AddRule 添加安全组规则
func (p *Provider) AddRule(groupID string, rule types.SecurityRule) error {
	panic("not implemented")
}

// RemoveRule 删除安全组规则
func (p *Provider) RemoveRule(groupID string, rule types.SecurityRule) error {
	panic("not implemented")
}

// UpdateRule 更新安全组规则
func (p *Provider) UpdateRule(groupID string, ruleID string, rule types.SecurityRule) error {
	panic("not implemented")
}

// GetRule 获取安全组规则详情
func (p *Provider) GetRule(groupID string, ruleID string) (*types.SecurityRule, error) {
	panic("not implemented")
}

// ListRules 获取安全组规则列表
func (p *Provider) ListRules(groupID string) ([]types.SecurityRule, error) {
	panic("not implemented")
}
