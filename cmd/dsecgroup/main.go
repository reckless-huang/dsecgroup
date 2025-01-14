package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/reckless-huang/dsecgroup/pkg/providers/aliyun"
	"github.com/reckless-huang/dsecgroup/pkg/types"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	provider   string
	region     string
	accessKey  string
	secretKey  string
	configFile = "config.yaml"
)

// Config 配置结构
type Config struct {
	CurrentRegion        string `yaml:"current_region"`
	CurrentInstance      string `yaml:"current_instance"`
	CurrentSecurityGroup string `yaml:"current_security_group"`
}

// 保存配置
func saveConfig(cfg Config) error {
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
}

// 读取配置
func loadConfig() (Config, error) {
	var cfg Config
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	err = yaml.Unmarshal(data, &cfg)
	return cfg, err
}

// 获取本地公网IP
func getLocalPublicIP() (string, error) {
	resp, err := http.Get("https://ip.me")
	if err != nil {
		return "", fmt.Errorf("get public IP failed: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read IP failed: %v", err)
	}

	// 提取纯 IP 地址
	ip := strings.TrimSpace(string(body))
	// 移除任何 HTML 标签和其他内容
	ip = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(ip, "")
	ip = strings.TrimSpace(ip)

	// 验证是否是有效的 IP 地址
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP address received: %s", ip)
	}

	return ip, nil
}

// 生成规则哈希
func generateRuleHash(rule types.SecurityRule) string {
	h := sha1.New()
	h.Write([]byte(rule.GetRuleKey()))
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "dsecgroup",
		Short: "Dynamic security group management tool",
	}

	// 修改全局标志的简写
	rootCmd.PersistentFlags().StringVar(&provider, "provider", "aliyun", "Cloud provider (aliyun)")
	rootCmd.PersistentFlags().StringVarP(&region, "region", "r", "", "Region ID")
	rootCmd.PersistentFlags().StringVar(&accessKey, "access-key", "", "Access Key ID")
	rootCmd.PersistentFlags().StringVar(&secretKey, "secret-key", "", "Access Key Secret")

	// 添加子命令
	rootCmd.AddCommand(
		newListRegionsCmd(),
		newListSecgroupsCmd(),
		newAddSecgroupRuleCmd(),
		newRemoveSecgroupRuleCmd(),
		newListSecgroupRulesCmd(),
		newSelectRegionCmd(),
		newListInstancesCmd(),
		newSelectInstanceCmd(),
		newListInstanceSecgroupsCmd(),
		newSelectSecgroupCmd(),
		newQuickAddLocalIPCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// 创建 Provider 实例
func createProvider() (types.SecurityGroupProvider, error) {
	// 优先从命令行参数获取凭证，如果没有则从环境变量获取
	ak := accessKey
	sk := secretKey

	if ak == "" {
		ak = os.Getenv("ALICLOUD_ACCESS_KEY")
	}
	if sk == "" {
		sk = os.Getenv("ALICLOUD_SECRET_KEY")
	}

	if ak == "" || sk == "" {
		return nil, fmt.Errorf("access-key and secret-key are required (can be set via ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY)")
	}

	config := types.SecurityGroupConfig{
		Provider: provider,
		Region:   region, // 可以为空
		Credential: map[string]string{
			"access_key_id":     ak,
			"access_key_secret": sk,
		},
	}

	return aliyun.NewProvider(config)
}

// 列出可用地域
func newListRegionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-regions",
		Short: "List available regions",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := createProvider()
			if err != nil {
				return err
			}

			regions, err := p.ListRegions()
			if err != nil {
				return err
			}

			for _, r := range regions {
				fmt.Printf("%s\t%s\n", r.RegionID, r.LocalName)
			}
			return nil
		},
	}
	return cmd
}

// 列出安全组
func newListSecgroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-secgroups",
		Short: "List security groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := createProvider()
			if err != nil {
				return err
			}

			groups, err := p.ListSecurityGroups()
			if err != nil {
				return err
			}

			for _, g := range groups {
				fmt.Printf("%s\t%s\t%s\n", g.GroupID, g.Name, g.Description)
			}
			return nil
		},
	}
	return cmd
}

// 添加规则
func newAddSecgroupRuleCmd() *cobra.Command {
	var (
		secgroupID string
		port       int
		ip         string
	)

	cmd := &cobra.Command{
		Use:   "add-secgroup-rule",
		Short: "Add security group rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := createProvider()
			if err != nil {
				return err
			}

			rule := types.SecurityRule{
				IP:        ip,
				Port:      port,
				Protocol:  "tcp",
				Direction: "ingress",
				Action:    types.ActionAllow,
				Priority:  1,
			}

			return p.AddRule(secgroupID, rule)
		},
	}

	cmd.Flags().StringVarP(&secgroupID, "secgroup-id", "g", "", "Security group ID")
	cmd.Flags().IntVarP(&port, "port", "P", 22, "Port number")
	cmd.Flags().StringVarP(&ip, "ip", "i", "", "IP address")
	cmd.MarkFlagRequired("secgroup-id")

	return cmd
}

// 删除规则
func newRemoveSecgroupRuleCmd() *cobra.Command {
	var (
		secgroupID string
		port       int
		ip         string
	)

	cmd := &cobra.Command{
		Use:   "remove-secgroup-rule",
		Short: "Remove security group rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := createProvider()
			if err != nil {
				return err
			}

			rule := types.SecurityRule{
				IP:        ip,
				Port:      port,
				Protocol:  "tcp",
				Direction: "ingress",
				Action:    types.ActionAllow,
				Priority:  1,
			}

			return p.RemoveRule(secgroupID, rule)
		},
	}

	cmd.Flags().StringVarP(&secgroupID, "secgroup-id", "g", "", "Security group ID")
	cmd.Flags().IntVarP(&port, "port", "P", 22, "Port number")
	cmd.Flags().StringVarP(&ip, "ip", "i", "", "IP address")
	cmd.MarkFlagRequired("secgroup-id")
	cmd.MarkFlagRequired("ip")

	return cmd
}

// 列出规则
func newListSecgroupRulesCmd() *cobra.Command {
	var secgroupID string

	cmd := &cobra.Command{
		Use:   "list-secgroup-rules",
		Short: "List security group rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 读取配置
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config failed: %v", err)
			}

			// 如果命令行没有指定安全组ID，则使用配置中的
			if secgroupID == "" {
				if cfg.CurrentSecurityGroup == "" {
					return fmt.Errorf("no security group specified or selected, please use --secgroup-id flag or select-secgroup command")
				}
				secgroupID = cfg.CurrentSecurityGroup
			}

			// 使用配置中的地域
			if cfg.CurrentRegion == "" {
				return fmt.Errorf("no region selected, please use select-region command first")
			}
			region = cfg.CurrentRegion

			p, err := createProvider()
			if err != nil {
				return err
			}

			fmt.Printf("Fetching rules for security group %s...\n", secgroupID)
			rules, err := p.ListRules(secgroupID)
			if err != nil {
				return err
			}

			fmt.Printf("\nFound %d rules:\n", len(rules))
			fmt.Printf("%-40s\t%-20s\t%-8s\t%-10s\t%-10s\t%-10s\t%-8s\t%s\n",
				"RULE HASH", "IP", "PORT", "PROTOCOL", "DIRECTION", "ACTION", "PRIORITY", "DESCRIPTION")
			for _, r := range rules {
				fmt.Printf("%-40s\t%-20s\t%-8d\t%-10s\t%-10s\t%-10s\t%-8d\t%s\n",
					r.RuleHash, r.IP, r.Port, r.Protocol, r.Direction, r.Action, r.Priority, r.Description)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&secgroupID, "secgroup-id", "g", "", "Security group ID (optional if group selected)")
	return cmd
}

// 选择地域命令
func newSelectRegionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "select-region [region-id]",
		Short: "Select and save current region",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			regionID := args[0]

			// 验证地域是否有效
			p, err := createProvider()
			if err != nil {
				return err
			}

			regions, err := p.ListRegions()
			if err != nil {
				return err
			}

			valid := false
			for _, r := range regions {
				if r.RegionID == regionID {
					valid = true
					break
				}
			}

			if !valid {
				return fmt.Errorf("invalid region ID: %s", regionID)
			}

			// 保存选择的地域
			cfg := Config{CurrentRegion: regionID}
			if err := saveConfig(cfg); err != nil {
				return fmt.Errorf("save config failed: %v", err)
			}

			fmt.Printf("Current region set to: %s\n", regionID)
			return nil
		},
	}
	return cmd
}

// 列出实例命令
func newListInstancesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-instances",
		Short: "List instances in current region",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 如果命令行没有指定地域，则从配置文件读取
			if region == "" {
				cfg, err := loadConfig()
				if err != nil {
					return fmt.Errorf("load config failed: %v", err)
				}
				if cfg.CurrentRegion == "" {
					return fmt.Errorf("no region selected, please use select-region command first")
				}
				region = cfg.CurrentRegion
			}
			fmt.Printf("Using region: %s\n", region)

			p, err := createProvider()
			if err != nil {
				return err
			}

			instanceProvider, ok := p.(types.InstanceProvider)
			if !ok {
				return fmt.Errorf("provider does not support instance operations")
			}

			fmt.Println("Fetching instances...")
			instances, err := instanceProvider.ListInstances()
			if err != nil {
				return err
			}

			fmt.Printf("Found %d instances\n", len(instances))
			for _, inst := range instances {
				fmt.Printf("ID: %s\tName: %s\tStatus: %s\tPrivateIP: %s\tPublicIP: %s\n",
					inst.InstanceID, inst.Name, inst.Status, inst.PrivateIP, inst.PublicIP)
			}
			return nil
		},
	}
	return cmd
}

// 选择实例命令
func newSelectInstanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "select-instance [instance-id]",
		Short: "Select and save current ECS instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instanceID := args[0]

			// 如果没有指定地域，从配置文件读取
			if region == "" {
				cfg, err := loadConfig()
				if err != nil {
					return fmt.Errorf("load config failed: %v", err)
				}
				if cfg.CurrentRegion == "" {
					return fmt.Errorf("no region selected, please use select-region command first")
				}
				region = cfg.CurrentRegion
			}

			// 验证实例是否存在
			p, err := createProvider()
			if err != nil {
				return err
			}

			instanceProvider, ok := p.(types.InstanceProvider)
			if !ok {
				return fmt.Errorf("provider does not support instance operations")
			}

			instance, err := instanceProvider.GetInstance(instanceID)
			if err != nil {
				return fmt.Errorf("instance not found: %v", err)
			}

			// 保存配置
			cfg := Config{
				CurrentRegion:   region,
				CurrentInstance: instanceID,
			}
			if err := saveConfig(cfg); err != nil {
				return fmt.Errorf("save config failed: %v", err)
			}

			fmt.Printf("Current instance set to: %s (%s)\n", instance.Name, instance.InstanceID)
			return nil
		},
	}
	return cmd
}

// 列出实例关联的安全组命令
func newListInstanceSecgroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-instance-secgroups",
		Short: "List security groups associated with current instance",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 读取配置
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config failed: %v", err)
			}
			if cfg.CurrentInstance == "" {
				return fmt.Errorf("no instance selected, please use select-instance command first")
			}
			if cfg.CurrentRegion == "" {
				return fmt.Errorf("no region selected, please use select-region command first")
			}

			// 使用配置中的地域
			region = cfg.CurrentRegion

			p, err := createProvider()
			if err != nil {
				return err
			}

			instanceProvider, ok := p.(types.InstanceProvider)
			if !ok {
				return fmt.Errorf("provider does not support instance operations")
			}

			fmt.Printf("Fetching security groups for instance %s...\n", cfg.CurrentInstance)
			groups, err := instanceProvider.ListInstanceSecurityGroups(cfg.CurrentInstance)
			if err != nil {
				return err
			}

			fmt.Printf("\nFound %d security groups:\n", len(groups))
			fmt.Printf("%-22s\t%-32s\t%s\n", "GROUP ID", "NAME", "DESCRIPTION")
			for _, g := range groups {
				fmt.Printf("%-22s\t%-32s\t%s\n", g.GroupID, g.Name, g.Description)
			}
			return nil
		},
	}
	return cmd
}

// 选择安全组命令
func newSelectSecgroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "select-secgroup [secgroup-id]",
		Short: "Select and save current security group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secgroupID := args[0]

			// 读取配置
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config failed: %v", err)
			}
			if cfg.CurrentRegion == "" {
				return fmt.Errorf("no region selected, please use select-region command first")
			}

			// 使用配置中的地域
			region = cfg.CurrentRegion

			// 验证安全组是否存在
			p, err := createProvider()
			if err != nil {
				return err
			}

			group, err := p.GetSecurityGroup(secgroupID)
			if err != nil {
				return fmt.Errorf("security group not found: %v", err)
			}

			// 保存配置
			cfg.CurrentSecurityGroup = secgroupID
			if err := saveConfig(cfg); err != nil {
				return fmt.Errorf("save config failed: %v", err)
			}

			fmt.Printf("Current security group set to: %s (%s)\n", group.Name, group.GroupID)

			// 如果有实例被选中，显示是否关联
			if cfg.CurrentInstance != "" {
				instanceProvider, ok := p.(types.InstanceProvider)
				if ok {
					groups, err := instanceProvider.ListInstanceSecurityGroups(cfg.CurrentInstance)
					if err == nil {
						associated := false
						for _, g := range groups {
							if g.GroupID == secgroupID {
								associated = true
								break
							}
						}
						if associated {
							fmt.Printf("This security group is associated with the current instance\n")
						} else {
							fmt.Printf("This security group is NOT associated with the current instance\n")
						}
					}
				}
			}

			return nil
		},
	}
	return cmd
}

// 快速添加本地IP规则命令
func newQuickAddLocalIPCmd() *cobra.Command {
	var (
		port     int
		allPorts bool
	)

	cmd := &cobra.Command{
		Use:   "quick-add-local",
		Short: "Add or update rule for local IP address",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 读取配置
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config failed: %v", err)
			}
			if cfg.CurrentSecurityGroup == "" {
				return fmt.Errorf("no security group selected, please use select-secgroup command first")
			}
			if cfg.CurrentRegion == "" {
				return fmt.Errorf("no region selected, please use select-region command first")
			}

			// 设置全局 region 变量
			region = cfg.CurrentRegion
			fmt.Printf("Using region: %s\n", region)

			// 获取本地公网IP
			ip, err := getLocalPublicIP()
			if err != nil {
				return err
			}
			ip = ip + "/32" // 转换为CIDR格式

			p, err := createProvider()
			if err != nil {
				return err
			}

			// 如果指定了 all-ports 或没有指定端口，则添加全端口规则
			if allPorts || !cmd.Flags().Changed("port") {
				rule := types.SecurityRule{
					IP:          ip,
					Port:        -1,
					Protocol:    "tcp",
					Direction:   "ingress",
					Action:      types.ActionAllow,
					Priority:    1,
					Description: "gen_by_dsecgroup (all ports)",
				}

				// 检查规则是否存在
				rules, err := p.ListRules(cfg.CurrentSecurityGroup)
				if err != nil {
					return err
				}

				// 使用 Provider 的规则哈希器比较规则
				if hasher, ok := p.(types.RuleHasher); ok {
					for _, existing := range rules {
						if hasher.IsRuleEqual(existing, rule) {
							fmt.Printf("Rule already exists for IP %s (all ports)\n", ip)
							return nil
						}
					}
				}

				// 添加新规则
				if err := p.AddRule(cfg.CurrentSecurityGroup, rule); err != nil {
					return fmt.Errorf("add rule failed: %v", err)
				}

				fmt.Printf("Successfully added rule for IP %s (all ports)\n", ip)
				return nil
			}

			// 添加指定端口的规则
			rule := types.SecurityRule{
				IP:          ip,
				Port:        port,
				Protocol:    "tcp",
				Direction:   "ingress",
				Action:      types.ActionAllow,
				Priority:    1,
				Description: fmt.Sprintf("gen_by_dsecgroup (port %d)", port),
			}

			// 检查规则是否存在
			rules, err := p.ListRules(cfg.CurrentSecurityGroup)
			if err != nil {
				return err
			}

			// 检查是否存在相同的规则（不使用哈希，直接比较关键字段）
			for _, existing := range rules {
				if existing.IP == ip &&
					existing.Port == port &&
					existing.Protocol == rule.Protocol &&
					existing.Direction == rule.Direction &&
					existing.Action == rule.Action {
					fmt.Printf("Rule already exists for IP %s on port %d\n", ip, port)
					return nil
				}
			}

			// 添加新规则
			if err := p.AddRule(cfg.CurrentSecurityGroup, rule); err != nil {
				return fmt.Errorf("add rule failed: %v", err)
			}

			fmt.Printf("Successfully added rule for IP %s on port %d\n", ip, port)
			return nil
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 22, "Port number to allow access")
	cmd.Flags().BoolVar(&allPorts, "all-ports", false, "Allow access to all ports")
	return cmd
}
