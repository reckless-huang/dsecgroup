package aliyun

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/reckless-huang/dsecgroup/pkg/types"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
)

// Provider 实现阿里云的安全组和实例操作
type Provider struct {
	client *ecs.Client
	region string
	RuleHasher
}

// NewProvider 创建阿里云 Provider 实例
func NewProvider(config types.SecurityGroupConfig) (*Provider, error) {
	// 只检查认证信息
	if config.Credential["access_key_id"] == "" || config.Credential["access_key_secret"] == "" {
		return nil, fmt.Errorf("access key and secret key are required")
	}

	client, err := ecs.NewClientWithAccessKey(
		config.Region, // 可以为空，某些 API 不需要 region
		config.Credential["access_key_id"],
		config.Credential["access_key_secret"],
	)
	if err != nil {
		return nil, fmt.Errorf("create aliyun client failed: %v", err)
	}

	return &Provider{
		client:     client,
		region:     config.Region,
		RuleHasher: RuleHasher{},
	}, nil
}

var _ types.SecurityGroupProvider = &Provider{}
var _ types.InstanceProvider = &Provider{}

// ListSecurityGroups 获取安全组列表
func (p *Provider) ListSecurityGroups() ([]types.SecurityGroup, error) {
	request := ecs.CreateDescribeSecurityGroupsRequest()
	request.RegionId = p.region

	response, err := p.client.DescribeSecurityGroups(request)
	if err != nil {
		return nil, fmt.Errorf("list security groups failed: %v", err)
	}

	groups := make([]types.SecurityGroup, 0, len(response.SecurityGroups.SecurityGroup))
	for _, g := range response.SecurityGroups.SecurityGroup {
		groups = append(groups, types.SecurityGroup{
			GroupID:     g.SecurityGroupId,
			Name:        g.SecurityGroupName,
			Description: g.Description,
			VpcID:       g.VpcId,
			CreatedAt:   g.CreationTime,
		})
	}

	return groups, nil
}

// GetSecurityGroup 获取安全组详情
func (p *Provider) GetSecurityGroup(groupID string) (*types.SecurityGroup, error) {
	request := ecs.CreateDescribeSecurityGroupAttributeRequest()
	request.SecurityGroupId = groupID
	request.RegionId = p.region

	response, err := p.client.DescribeSecurityGroupAttribute(request)
	if err != nil {
		return nil, fmt.Errorf("get security group failed: %v", err)
	}

	return &types.SecurityGroup{
		GroupID:     response.SecurityGroupId,
		Name:        response.SecurityGroupName,
		Description: response.Description,
		VpcID:       response.VpcId,
		CreatedAt:   "",
	}, nil
}

// CreateSecurityGroup 创建安全组
func (p *Provider) CreateSecurityGroup(name, description string) (*types.SecurityGroup, error) {
	request := ecs.CreateCreateSecurityGroupRequest()
	request.RegionId = p.region
	request.SecurityGroupName = name
	request.Description = description

	response, err := p.client.CreateSecurityGroup(request)
	if err != nil {
		return nil, fmt.Errorf("create security group failed: %v", err)
	}

	return &types.SecurityGroup{
		GroupID:     response.SecurityGroupId,
		Name:        name,
		Description: description,
		CreatedAt:   "", // 需要额外调用获取
	}, nil
}

// DeleteSecurityGroup 删除安全组
func (p *Provider) DeleteSecurityGroup(groupID string) error {
	request := ecs.CreateDeleteSecurityGroupRequest()
	request.RegionId = p.region
	request.SecurityGroupId = groupID

	_, err := p.client.DeleteSecurityGroup(request)
	if err != nil {
		return fmt.Errorf("delete security group failed: %v", err)
	}

	return nil
}

// AddRule 添加安全组规则
func (p *Provider) AddRule(groupID string, rule types.SecurityRule) error {
	request := ecs.CreateAuthorizeSecurityGroupRequest()
	request.RegionId = p.region
	request.SecurityGroupId = groupID
	request.NicType = "intranet" // 默认为内网

	// 设置协议和端口
	if rule.Port == -1 {
		request.IpProtocol = "all"
		request.PortRange = "-1/-1" // 阿里云使用 -1/-1 表示所有端口
	} else {
		request.IpProtocol = rule.Protocol
		request.PortRange = fmt.Sprintf("%d/%d", rule.Port, rule.Port)
	}

	request.SourceCidrIp = rule.IP

	// 转换 Action 为阿里云的策略值
	switch rule.Action {
	case types.ActionAllow:
		request.Policy = "accept"
	case types.ActionDeny:
		request.Policy = "drop"
	default:
		request.Policy = "accept"
	}

	request.Priority = fmt.Sprintf("%d", rule.Priority)
	request.Description = rule.Description

	// 打印关键参数
	slog.Debug("AddRule", "rule", rule)
	slog.Debug("RegionId", "region", request.RegionId)
	slog.Debug("SecurityGroupId", "group", request.SecurityGroupId)
	slog.Debug("IpProtocol", "protocol", request.IpProtocol)
	slog.Debug("PortRange", "port", request.PortRange)
	slog.Debug("SourceCidrIp", "ip", request.SourceCidrIp)
	slog.Debug("Policy", "policy", request.Policy)
	slog.Debug("Priority", "priority", request.Priority)
	slog.Debug("Description", "desc", request.Description)
	slog.Debug("NicType", "nic", request.NicType)

	_, err := p.client.AuthorizeSecurityGroup(request)
	if err != nil {
		return fmt.Errorf("add security group rule failed: %v", err)
	}

	return nil
}

// RemoveRule 删除安全组规则
func (p *Provider) RemoveRule(groupID string, rule types.SecurityRule) error {
	request := ecs.CreateRevokeSecurityGroupRequest()
	request.RegionId = p.region
	request.SecurityGroupId = groupID

	// 如果有规则ID，只使用规则ID
	if rule.RuleID != "" {
		request.SecurityGroupRuleId = &[]string{rule.RuleID}
	} else {
		// 否则使用其他参数匹配规则
		if rule.Port == -1 {
			request.IpProtocol = "all"
			request.PortRange = "-1/-1"
		} else {
			request.IpProtocol = rule.Protocol
			request.PortRange = fmt.Sprintf("%d/%d", rule.Port, rule.Port)
		}
		request.SourceCidrIp = rule.IP
		request.Policy = string(rule.Action)
		request.Priority = fmt.Sprintf("%d", rule.Priority)
		request.Description = rule.Description
	}

	_, err := p.client.RevokeSecurityGroup(request)
	if err != nil {
		return fmt.Errorf("remove security group rule failed: %v", err)
	}

	return nil
}

// UpdateRule 更新安全组规则
func (p *Provider) UpdateRule(groupID string, ruleID string, rule types.SecurityRule) error {
	// 阿里云不支持直接更新规则，需要先删除再添加

	// 创建删除请求，只使用规则ID
	removeRequest := ecs.CreateRevokeSecurityGroupRequest()
	removeRequest.RegionId = p.region
	removeRequest.SecurityGroupId = groupID
	removeRequest.SecurityGroupRuleId = &[]string{rule.RuleID}

	// 执行删除
	_, err := p.client.RevokeSecurityGroup(removeRequest)
	if err != nil {
		return fmt.Errorf("remove old rule failed: %v", err)
	}

	// 添加新规则
	return p.AddRule(groupID, rule)
}

// GetRule 获取安全组规则详情
func (p *Provider) GetRule(groupID string, ruleID string) (*types.SecurityRule, error) {
	request := ecs.CreateDescribeSecurityGroupAttributeRequest()
	request.SecurityGroupId = groupID
	request.RegionId = p.region

	response, err := p.client.DescribeSecurityGroupAttribute(request)
	if err != nil {
		return nil, fmt.Errorf("get security group rule failed: %v", err)
	}

	// 需要在返回的规则列表中查找匹配的规则
	// 这里简单实现，实际可能需要更复杂的匹配逻辑
	for _, r := range response.Permissions.Permission {
		if r.SourceCidrIp == ruleID { // 使用 IP 作为规则 ID
			return &types.SecurityRule{
				IP:       r.SourceCidrIp,
				Port:     parsePort(r.PortRange),
				Protocol: r.IpProtocol,
				Action:   types.Action(r.Policy),
				Priority: parsePriority(r.Priority),
			}, nil
		}
	}

	return nil, types.ErrRuleNotFound
}

// 生成规则哈希
func generateRuleHash(r types.SecurityRule) string {
	h := sha1.New()
	h.Write([]byte(r.GetRuleKey()))
	return hex.EncodeToString(h.Sum(nil))
}

// ListRules 获取安全组规则列表
func (p *Provider) ListRules(groupID string) ([]types.SecurityRule, error) {
	request := ecs.CreateDescribeSecurityGroupAttributeRequest()
	request.SecurityGroupId = groupID
	request.RegionId = p.region

	response, err := p.client.DescribeSecurityGroupAttribute(request)
	if err != nil {
		return nil, fmt.Errorf("list security group rules failed: %v", err)
	}

	rules := make([]types.SecurityRule, 0, len(response.Permissions.Permission))
	for _, r := range response.Permissions.Permission {
		rule := types.SecurityRule{
			RuleID:      r.SecurityGroupRuleId, // 云厂商规则ID
			IP:          r.SourceCidrIp,
			Port:        parsePort(r.PortRange),
			Protocol:    r.IpProtocol,
			Direction:   r.Direction,
			Action:      types.Action(r.Policy),
			Priority:    parsePriority(r.Priority),
			Description: r.Description,
		}
		// 生成本地哈希，用于跨云规则匹配
		rule.RuleHash = p.GenerateRuleHash(rule)
		rules = append(rules, rule)
	}

	return rules, nil
}

// ListRegions 获取阿里云可用地域列表
func (p *Provider) ListRegions() ([]types.Region, error) {
	request := ecs.CreateDescribeRegionsRequest()
	request.AcceptLanguage = "zh-CN"
	// 使用默认地域 cn-hangzhou
	request.RegionId = "cn-hangzhou"

	response, err := p.client.DescribeRegions(request)
	if err != nil {
		return nil, fmt.Errorf("list regions failed: %v", err)
	}

	regions := make([]types.Region, 0, len(response.Regions.Region))
	for _, r := range response.Regions.Region {
		regions = append(regions, types.Region{
			RegionID:  r.RegionId,
			LocalName: r.LocalName,
		})
	}

	return regions, nil
}

// ListInstances 获取实例列表
func (p *Provider) ListInstances() ([]types.Instance, error) {
	slog.Debug("Requesting instances for region: %s\n", p.region)
	request := ecs.CreateDescribeInstancesRequest()
	request.RegionId = p.region

	response, err := p.client.DescribeInstances(request)
	if err != nil {
		return nil, fmt.Errorf("list instances failed: %v", err)
	}

	// 打印完整响应
	slog.Debug("API Response Details: %+v\n", response)
	slog.Debug("Total Count: %d\n", response.TotalCount)
	slog.Debug("Page Size: %d\n", response.PageSize)
	slog.Debug("Page Number: %d\n", response.PageNumber)
	slog.Debug("Request ID: %s\n", response.RequestId)

	// 打印每个实例的详细信息
	for _, i := range response.Instances.Instance {
		slog.Debug("\n----------------------------------------\n")
		slog.Debug("Instance ID: %s\n", i.InstanceId)
		slog.Debug("Name: %s\n", i.InstanceName)
		slog.Debug("Status: %s\n", i.Status)
		slog.Debug("Instance Type: %s\n", i.InstanceType)
		slog.Debug("OS: %s\n", i.OSNameEn)
		slog.Debug("Zone: %s\n", i.ZoneId)
		slog.Debug("Private IP: %v\n", i.VpcAttributes.PrivateIpAddress.IpAddress)
		slog.Debug("Public IP: %v\n", i.PublicIpAddress.IpAddress)
		slog.Debug("Security Groups: %v\n", i.SecurityGroupIds.SecurityGroupId)
		slog.Debug("Created Time: %s\n", i.CreationTime)
		slog.Debug("----------------------------------------\n")
	}

	instances := make([]types.Instance, 0, len(response.Instances.Instance))
	for _, i := range response.Instances.Instance {
		instances = append(instances, types.Instance{
			InstanceID:       i.InstanceId,
			Name:             i.InstanceName,
			Status:           i.Status,
			PrivateIP:        i.VpcAttributes.PrivateIpAddress.IpAddress[0],
			PublicIP:         getPublicIP(i),
			SecurityGroupIDs: i.SecurityGroupIds.SecurityGroupId,
			Region:           p.region,
		})
	}

	return instances, nil
}

func getPublicIP(instance ecs.Instance) string {
	if len(instance.PublicIpAddress.IpAddress) > 0 {
		return instance.PublicIpAddress.IpAddress[0]
	}
	if instance.EipAddress.IpAddress != "" {
		return instance.EipAddress.IpAddress
	}
	return ""
}

// 辅助函数
func parsePort(portRange string) int {
	// 简单实现，实际需要更复杂的解析
	var port int
	fmt.Sscanf(portRange, "%d/%d", &port)
	return port
}

func parsePriority(priority string) int {
	var p int
	fmt.Sscanf(priority, "%d", &p)
	return p
}

// GetInstance 获取单个实例详情
func (p *Provider) GetInstance(instanceID string) (*types.Instance, error) {
	request := ecs.CreateDescribeInstancesRequest()
	request.RegionId = p.region
	request.InstanceIds = fmt.Sprintf("[\"%s\"]", instanceID)

	response, err := p.client.DescribeInstances(request)
	if err != nil {
		return nil, fmt.Errorf("get instance failed: %v", err)
	}

	if len(response.Instances.Instance) == 0 {
		return nil, fmt.Errorf("instance not found: %s", instanceID)
	}

	i := response.Instances.Instance[0]
	return &types.Instance{
		InstanceID:       i.InstanceId,
		Name:             i.InstanceName,
		Status:           i.Status,
		PrivateIP:        i.VpcAttributes.PrivateIpAddress.IpAddress[0],
		PublicIP:         getPublicIP(i),
		SecurityGroupIDs: i.SecurityGroupIds.SecurityGroupId,
		Region:           p.region,
	}, nil
}

// ListInstanceSecurityGroups 获取实例关联的安全组
func (p *Provider) ListInstanceSecurityGroups(instanceID string) ([]types.SecurityGroup, error) {
	instance, err := p.GetInstance(instanceID)
	if err != nil {
		return nil, err
	}

	groups := make([]types.SecurityGroup, 0, len(instance.SecurityGroupIDs))
	for _, groupID := range instance.SecurityGroupIDs {
		group, err := p.GetSecurityGroup(groupID)
		if err != nil {
			return nil, err
		}
		groups = append(groups, *group)
	}

	return groups, nil
}

// AddInstanceToSecurityGroup 将实例添加到安全组
func (p *Provider) AddInstanceToSecurityGroup(instanceID, securityGroupID string) error {
	request := ecs.CreateJoinSecurityGroupRequest()
	request.RegionId = p.region
	request.InstanceId = instanceID
	request.SecurityGroupId = securityGroupID

	_, err := p.client.JoinSecurityGroup(request)
	if err != nil {
		return fmt.Errorf("add instance to security group failed: %v", err)
	}

	return nil
}

// RemoveInstanceFromSecurityGroup 将实例从安全组中移除
func (p *Provider) RemoveInstanceFromSecurityGroup(instanceID, securityGroupID string) error {
	request := ecs.CreateLeaveSecurityGroupRequest()
	request.RegionId = p.region
	request.InstanceId = instanceID
	request.SecurityGroupId = securityGroupID

	_, err := p.client.LeaveSecurityGroup(request)
	if err != nil {
		return fmt.Errorf("remove instance from security group failed: %v", err)
	}

	return nil
}
