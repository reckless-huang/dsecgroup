package types

// Instance 表示云服务器实例
type Instance struct {
	InstanceID       string   `json:"instance_id"`
	Name             string   `json:"name"`
	Status           string   `json:"status"`
	PrivateIP        string   `json:"private_ip"`
	PublicIP         string   `json:"public_ip"`
	SecurityGroupIDs []string `json:"security_group_ids"`
	Region           string   `json:"region"`
}

// InstanceProvider 定义了云服务器操作的接口
type InstanceProvider interface {
	// ListInstances 获取账号下的所有实例
	ListInstances() ([]Instance, error)

	// GetInstance 获取单个实例详情
	GetInstance(instanceID string) (*Instance, error)

	// ListInstanceSecurityGroups 获取实例关联的安全组
	ListInstanceSecurityGroups(instanceID string) ([]SecurityGroup, error)

	// AddInstanceToSecurityGroup 将实例添加到安全组
	AddInstanceToSecurityGroup(instanceID, securityGroupID string) error

	// RemoveInstanceFromSecurityGroup 将实例从安全组中移除
	RemoveInstanceFromSecurityGroup(instanceID, securityGroupID string) error
}
