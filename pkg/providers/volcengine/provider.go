package volcengine

import (
	"fmt"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"log/slog"

	"github.com/reckless-huang/dsecgroup/pkg/types"
	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

type Provider struct {
	client            *ecs.ECS
	vpcClient         *vpc.VPC
	currentInstanceId string
	region            string
	types.RuleHasher
}

func (p *Provider) GetInstance(instanceID string) (*types.Instance, error) {
	slog.Debug("Getting instance details", "instance_id", instanceID, "region", p.region)
	request := &ecs.DescribeInstancesInput{}

	response, err := p.client.DescribeInstances(request)
	if err != nil {
		return nil, fmt.Errorf("get instance failed: %v", err)
	}

	// 遍历实例列表查找匹配的实例ID
	for _, i := range response.Instances {
		if *i.InstanceId == instanceID {
			// 获取公网IP，如果有的话
			var publicIP string
			if i.EipAddress != nil {
				publicIP = *i.EipAddress.IpAddress
			}

			// 获取网卡id
			var cniIDs []*string
			for _, cni := range i.NetworkInterfaces {
				cniIDs = append(cniIDs, cni.NetworkInterfaceId)
			}
			// 获取私网IP，如果有的话
			var privateIP string
			if len(i.NetworkInterfaces) > 0 {
				privateIP = *i.NetworkInterfaces[0].PrimaryIpAddress
			}

			return &types.Instance{
				InstanceID:       *i.InstanceId,
				Name:             *i.InstanceName,
				Status:           *i.Status,
				PrivateIP:        privateIP,
				PublicIP:         publicIP,
				SecurityGroupIDs: []string{}, // 暂时设置为空切片，等待安全组API实现
				Region:           p.region,
				CNIID:            cniIDs,
			}, nil
		}
	}

	return nil, fmt.Errorf("instance not found: %s", instanceID)
}

func (p *Provider) ListInstanceSecurityGroups(instanceID string) ([]types.SecurityGroup, error) {
	instance, getInstanceErr := p.GetInstance(instanceID)
	if getInstanceErr != nil {
		slog.Error("Get instance failed", "err", getInstanceErr)
		return nil, getInstanceErr
	}
	// 获取id
	secGroupIDs := []string{}
	for _, cniID := range instance.CNIID {
		describeNetworkInterfaceAttributesInput := &vpc.DescribeNetworkInterfaceAttributesInput{
			NetworkInterfaceId: cniID,
		}

		// 复制代码运行示例，请自行打印API返回值。
		res, err := p.vpcClient.DescribeNetworkInterfaceAttributes(describeNetworkInterfaceAttributesInput)
		if err != nil {
			slog.Error("DescribeNetworkInterfaceAttributes failed", "err", err)
			return nil, err
		} else {
			for _, group := range res.SecurityGroupIds {
				secGroupIDs = append(secGroupIDs, *group)
			}
		}
	}
	var securityGroups []types.SecurityGroup
	// 获取详情
	for _, secGroupID := range secGroupIDs {
		describeSecurityGroupAttributesInput := &vpc.DescribeSecurityGroupAttributesInput{
			SecurityGroupId: volcengine.String(secGroupID),
		}

		res, err := p.vpcClient.DescribeSecurityGroupAttributes(describeSecurityGroupAttributesInput)
		if err != nil {
			slog.Error("DescribeNetworkInterfaceAttributes failed", "err", err)
			return nil, fmt.Errorf("DescribeNetworkInterfaceAttributes failed", "err", err)
		}
		securityGroups = append(securityGroups, types.SecurityGroup{
			GroupID:     secGroupID,
			Name:        *res.SecurityGroupName,
			Description: *res.Description,
			VpcID:       *res.VpcId,
			CreatedAt:   "",
		})
	}
	return securityGroups, nil
}

func (p *Provider) AddInstanceToSecurityGroup(instanceID, securityGroupID string) error {
	//TODO implement me
	panic("implement me")
}

func (p *Provider) RemoveInstanceFromSecurityGroup(instanceID, securityGroupID string) error {
	//TODO implement me
	panic("implement me")
}

var _ types.SecurityGroupProvider = &Provider{}
var _ types.InstanceProvider = &Provider{}

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
	vpcClient := vpc.New(sess)
	if vpcClient == nil {
		return nil, fmt.Errorf("create volcengine vpc client failed")
	}
	return &Provider{
		client:            client,
		region:            config.Region,
		vpcClient:         vpcClient,
		RuleHasher:        &RuleHasher{},
		currentInstanceId: config.CurrentInstanceId,
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
	return p.ListInstanceSecurityGroups(p.currentInstanceId)
}

// GetSecurityGroup 获取安全组详情
func (p *Provider) GetSecurityGroup(groupID string) (*types.SecurityGroup, error) {
	describeSecurityGroupAttributesInput := &vpc.DescribeSecurityGroupAttributesInput{
		SecurityGroupId: volcengine.String(groupID),
	}

	res, err := p.vpcClient.DescribeSecurityGroupAttributes(describeSecurityGroupAttributesInput)
	if err != nil {
		slog.Error("DescribeNetworkInterfaceAttributes failed", "err", err)
		return nil, fmt.Errorf("DescribeNetworkInterfaceAttributes failed", "err", err)
	}
	return &types.SecurityGroup{
		GroupID:     groupID,
		Name:        *res.SecurityGroupName,
		Description: *res.Description,
		VpcID:       *res.VpcId,
		CreatedAt:   "",
	}, nil
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

// ListInstances 获取账号下的所有实例
func (p *Provider) ListInstances() ([]types.Instance, error) {
	slog.Debug("Requesting instances for region", "region", p.region)
	request := &ecs.DescribeInstancesInput{}
	// TODO(huangyf) 这里需要处理分页
	response, err := p.client.DescribeInstances(request)
	if err != nil {
		return nil, fmt.Errorf("list instances failed: %v", err)
	}

	// 打印调试信息
	slog.Debug("API Response Details", "response", response)

	instances := make([]types.Instance, 0)
	for _, i := range response.Instances {
		// 获取公网IP，如果有的话
		var publicIP string
		if i.EipAddress != nil {
			publicIP = *i.EipAddress.IpAddress
		}

		// 获取私网IP，如果有的话
		var privateIP string
		if len(i.NetworkInterfaces) > 0 {
			privateIP = *i.NetworkInterfaces[0].PrimaryIpAddress
		}

		instances = append(instances, types.Instance{
			InstanceID:       *i.InstanceId,
			Name:             *i.InstanceName,
			Status:           *i.Status,
			PrivateIP:        privateIP,
			PublicIP:         publicIP,
			SecurityGroupIDs: []string{}, // 暂时设置为空切片，等待安全组API实现
			Region:           p.region,
		})
	}

	return instances, nil
}
