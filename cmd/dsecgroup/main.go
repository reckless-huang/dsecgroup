package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/reckless-huang/dsecgroup/pkg/providers"

	"github.com/olekukonko/tablewriter"
	"github.com/reckless-huang/dsecgroup/pkg/providers/aliyun"
	"github.com/reckless-huang/dsecgroup/pkg/providers/volcengine"
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
	Aliyun      *ProviderConfig   `yaml:"aliyun,omitempty"`
	Volcengine  *ProviderConfig   `yaml:"volcengine,omitempty"`
	Log         LogConfig         `yaml:"log"`
	RuleAliases map[string]string `yaml:"rule_aliases"`
}

// ProviderConfig 云服务商配置结构
type ProviderConfig struct {
	AccessKey            string `yaml:"access_key"`
	SecretKey            string `yaml:"secret_key"`
	Region               string `yaml:"region"`
	CurrentInstance      string `yaml:"current_instance,omitempty"`
	CurrentSecurityGroup string `yaml:"current_security_group,omitempty"`
}

// 添加日志配置结构
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
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
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			Host:   "ip.me",
		},
		Header: map[string][]string{
			"User-Agent": {"curl/7.68.0"},
			"Accept":     {"*/*"},
		},
	}
	client := &http.Client{
		Transport: &http.Transport{
			// 指定ipv4
		},
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
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

	// 验证是否是有效的 IP 地址
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP address received: %s", ip)
	}

	return ip, nil
}

func initLogger(cfg LogConfig) {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
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

	// 初始化日志
	cfg, err := loadConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	initLogger(cfg.Log)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// 创建 Provider 实例
func createProvider() (types.SecurityGroupProvider, error) {
	// 优先从命令行参数获取凭证
	ak := accessKey
	sk := secretKey
	cfg, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("load config failed: %v", err)
	}
	// 如果命令行参数没有提供，则从配置文件获取
	if ak == "" || sk == "" {
		// 从对应云服务商的配置中获取认证信息
		switch provider {
		case providers.ALIYUN:
			if cfg.Aliyun != nil {
				ak = cfg.Aliyun.AccessKey
				sk = cfg.Aliyun.SecretKey
			}
		case providers.VOLCENGINE:
			if cfg.Volcengine != nil {
				ak = cfg.Volcengine.AccessKey
				sk = cfg.Volcengine.SecretKey
			}
		}
	}

	// 如果配置文件中有认证信息，就不再从环境变量获取
	if ak == "" || sk == "" {
		// 配置文件中没有认证信息，尝试从环境变量获取
		switch provider {
		case providers.ALIYUN:
			ak = os.Getenv("ALICLOUD_ACCESS_KEY")
			sk = os.Getenv("ALICLOUD_SECRET_KEY")
		case providers.VOLCENGINE:
			ak = os.Getenv("VOLCENGINE_ACCESS_KEY")
			sk = os.Getenv("VOLCENGINE_SECRET_KEY")
		}
	}

	if ak == "" || sk == "" {
		return nil, fmt.Errorf("access-key and secret-key are required (can be set via %s_ACCESS_KEY and %s_SECRET_KEY)", strings.ToUpper(provider), strings.ToUpper(provider))
	}

	config := types.SecurityGroupConfig{
		Provider: provider,
		Region:   region, // 可以为空
		Credential: map[string]string{
			"access_key_id":     ak,
			"access_key_secret": sk,
		},
	}

	switch provider {
	case providers.ALIYUN:
		return aliyun.NewProvider(config)
	case providers.VOLCENGINE:
		config.CurrentInstanceId = cfg.Volcengine.CurrentInstance
		return volcengine.NewProvider(config)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
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

			// 创建表格
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Region ID", "Local Name"})

			for _, r := range regions {
				table.Append([]string{r.RegionID, r.LocalName})
			}
			// 渲染表格
			table.Render()
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
			// 读取配置
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config failed: %v", err)
			}

			// 从对应云服务商的配置中获取region
			var currentRegion string
			switch provider {
			case "aliyun":
				if cfg.Aliyun != nil {
					currentRegion = cfg.Aliyun.Region
				}
			case "volcengine":
				if cfg.Volcengine != nil {
					currentRegion = cfg.Volcengine.Region
				}
			}
			if currentRegion == "" {
				return fmt.Errorf("no region selected for provider %s, please use select-region command first", provider)
			}
			region = currentRegion
			fmt.Printf("Current region: %s\n", currentRegion)
			p, err := createProvider()
			if err != nil {
				return err
			}
			secGroups, err := p.ListSecurityGroups()
			if err != nil {
				return err
			}

			// 创建表格
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"SecGroup ID", "Name", "Description"})

			for _, sg := range secGroups {
				table.Append([]string{sg.GroupID, sg.Name, sg.Description})
			}

			// 渲染表格
			table.Render()
			return nil
		},
	}
	return cmd
}

// 添加规则
func newAddSecgroupRuleCmd() *cobra.Command {
	var (
		secgroupID string
		ip         string
		port       int
	)

	cmd := &cobra.Command{
		Use:   "add-secgroup-rule",
		Short: "Add security group rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 读取配置
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config failed: %v", err)
			}

			var currentProviderConfig *ProviderConfig
			switch provider {
			case providers.ALIYUN:
				currentProviderConfig = cfg.Aliyun
			case providers.VOLCENGINE:
				currentProviderConfig = cfg.Volcengine
			}
			if currentProviderConfig == nil {
				return fmt.Errorf("no provider config found for provider %s", provider)
			}

			// 从对应云服务商的配置中获取region
			if region == "" {
				if currentProviderConfig.Region != "" {
					region = currentProviderConfig.Region
				} else {
					slog.Error("no region specified or selected")
					return fmt.Errorf("no region specified or selected")
				}
			}

			// 如果未指定安全组ID，使用当前选择的安全组
			if secgroupID == "" {
				if currentProviderConfig.CurrentSecurityGroup == "" {
					return fmt.Errorf("no security group specified or selected")
				}
				secgroupID = currentProviderConfig.CurrentSecurityGroup
			}

			// 检查必要参数
			if ip == "" {
				return fmt.Errorf("ip is required")
			}

			// 创建provider
			p, err := createProvider()
			if err != nil {
				return err
			}

			// 创建规则
			rule := types.SecurityRule{
				IP:          ip,
				Port:        port,
				Protocol:    "tcp",
				Direction:   "ingress",
				Action:      "accept",
				Priority:    1,
				Description: fmt.Sprintf("dsecgroup-port-%d", port),
			}

			// 如果端口为 -1，表示所有端口
			if port == -1 {
				rule.Protocol = "all"
				rule.Description = "dsecgroup-all-ports"
			}

			return p.AddRule(secgroupID, rule)
		},
	}

	cmd.Flags().StringVarP(&secgroupID, "secgroup-id", "g", "", "Security group ID")
	cmd.Flags().StringVarP(&ip, "ip", "i", "", "IP address")
	cmd.Flags().IntVarP(&port, "port", "P", 22, "Port number (-1 for all ports)")

	return cmd
}

// 修改删除规则命令
func newRemoveSecgroupRuleCmd() *cobra.Command {
	var (
		secgroupID string
		ruleID     string // 保持为字符串，但支持逗号分隔
		alias      string
	)

	cmd := &cobra.Command{
		Use:   "remove-secgroup-rule",
		Short: "Remove security group rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 读取配置
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config failed: %v", err)
			}
			var currentProviderConfig *ProviderConfig
			switch provider {
			case providers.ALIYUN:
				currentProviderConfig = cfg.Aliyun
			case providers.VOLCENGINE:
				currentProviderConfig = cfg.Volcengine
			}
			if currentProviderConfig == nil {
				return fmt.Errorf("no provider config found for provider %s", provider)
			}
			// 从对应云服务商的配置中获取region
			if region == "" {
				if currentProviderConfig.Region != "" {
					region = currentProviderConfig.Region
				} else {
					slog.Error("no region specified or selected")
					return fmt.Errorf("no region specified or selected")
				}
			}
			if secgroupID == "" {
				if currentProviderConfig.CurrentSecurityGroup != "" {
					secgroupID = currentProviderConfig.CurrentSecurityGroup
				} else {
					slog.Error("no security group specified or selected")
					return fmt.Errorf("no security group specified or selected")
				}
			}
			slog.Debug("Using region", "region", region)
			slog.Debug("Using security group", "security_group_id", secgroupID)

			p, err := createProvider()
			if err != nil {
				return err
			}

			// 获取所有规则
			rules, err := p.ListRules(secgroupID)
			if err != nil {
				return err
			}

			// 如果指定了规则ID，直接删除
			if ruleID != "" {
				// 分割规则ID
				ruleIDs := strings.Split(ruleID, ",")
				slog.Debug("Removing rules by ID", "rule_ids", ruleIDs)

				for _, ruleID := range ruleIDs {
					for _, rule := range rules {
						if rule.RuleHash == ruleID {
							if err := p.RemoveRule(secgroupID, rule); err != nil {
								return err
							}
							slog.Info("Rule removed", "rule_id", ruleID)
						}
					}
				}
				return nil
			}

			// 如果指定了别名，通过描述匹配删除
			if alias != "" {
				aliasDesc := alias
				if desc, ok := cfg.RuleAliases[alias]; ok {
					aliasDesc = desc
				}

				var matchRules []types.SecurityRule
				for _, rule := range rules {
					if strings.Contains(rule.Description, fmt.Sprintf("(%s", aliasDesc)) {
						matchRules = append(matchRules, rule)
					}
				}

				if len(matchRules) == 0 {
					return fmt.Errorf("no rules found with alias: %s", alias)
				}

				slog.Info("Removing rules", "count", len(matchRules))
				for _, rule := range matchRules {
					if err := p.RemoveRule(secgroupID, rule); err != nil {
						return err
					}
					slog.Info("Rule removed", "rule_id", rule.RuleHash)
				}
				return nil
			}

			return fmt.Errorf("either rule IDs or --alias must be specified")
		},
	}

	cmd.Flags().StringVarP(&secgroupID, "secgroup-id", "g", "", "Security group ID (optional if group selected)")
	cmd.Flags().StringVarP(&ruleID, "rule-id", "i", "", "Rule ID to remove (comma separated for multiple)")
	cmd.Flags().StringVarP(&alias, "alias", "a", "", "Rule alias to remove")
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
			var currentProviderConfig *ProviderConfig
			switch provider {
			case providers.ALIYUN:
				currentProviderConfig = cfg.Aliyun
			case providers.VOLCENGINE:
				currentProviderConfig = cfg.Volcengine
			}
			if currentProviderConfig == nil {
				return fmt.Errorf("no provider config found for provider %s", provider)
			}
			// 从对应云服务商的配置中获取region
			if region == "" {
				if currentProviderConfig.Region != "" {
					region = currentProviderConfig.Region
				} else {
					slog.Error("no region specified or selected")
					return fmt.Errorf("no region specified or selected")
				}
			}
			if secgroupID == "" {
				if currentProviderConfig.CurrentSecurityGroup != "" {
					secgroupID = currentProviderConfig.CurrentSecurityGroup
				} else {
					slog.Error("no security group specified or selected")
					return fmt.Errorf("no security group specified or selected")
				}
			}
			slog.Debug("Using region", "region", region)
			slog.Debug("Using security group", "security_group_id", secgroupID)

			p, err := createProvider()
			if err != nil {
				return err
			}

			slog.Info("Fetching rules for security group", "secgroup-id", secgroupID)
			rules, err := p.ListRules(secgroupID)
			if err != nil {
				return err
			}

			// 创建表格
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Rule ID", "IP", "Protocol", "Port", "Direction", "Action", "Priority", "Description"})

			for _, rule := range rules {
				table.Append([]string{rule.RuleHash, rule.IP, rule.Protocol, strconv.Itoa(rule.Port), rule.Direction, string(rule.Action), strconv.Itoa(rule.Priority), rule.Description})
			}

			// 渲染表格
			table.Render()
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
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config failed: %v", err)
			}
			// 保存选择的地域
			switch provider {
			case providers.ALIYUN:
				cfg.Aliyun.Region = regionID
			case providers.VOLCENGINE:
				cfg.Volcengine.Region = regionID
			}
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
				var currentRegion string
				switch provider {
				case "aliyun":
					if cfg.Aliyun != nil {
						currentRegion = cfg.Aliyun.Region
					}
				case "volcengine":
					if cfg.Volcengine != nil {
						currentRegion = cfg.Volcengine.Region
					}
				}
				if currentRegion == "" {
					return fmt.Errorf("no region selected for provider %s, please use select-region command first", provider)
				}
				region = currentRegion
			}
			slog.Info("Using region", "region", region)

			p, err := createProvider()
			if err != nil {
				return err
			}

			instanceProvider, ok := p.(types.InstanceProvider)
			if !ok {
				return fmt.Errorf("provider does not support instance operations")
			}

			slog.Info("Fetching instances...")
			instances, err := instanceProvider.ListInstances()
			if err != nil {
				return err
			}

			slog.Info("Found instances", "count", len(instances))

			// 创建表格
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"ID", "NAME", "STATUS", "PRIVATE_IP", "PUBLIC_IP"})

			for _, inst := range instances {
				table.Append([]string{inst.InstanceID, inst.Name, inst.Status, inst.PrivateIP, inst.PublicIP})
			}

			// 渲染表格
			table.Render()

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
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("load config failed: %v", err)
			}
			// 如果没有指定地域，从配置文件读取
			if region == "" {
				// 从对应云服务商的配置中获取region
				var currentRegion string
				switch provider {
				case "aliyun":
					if cfg.Aliyun != nil {
						currentRegion = cfg.Aliyun.Region
					}
				case "volcengine":
					if cfg.Volcengine != nil {
						currentRegion = cfg.Volcengine.Region
					}
				}
				if currentRegion == "" {
					return fmt.Errorf("no region selected for provider %s, please use select-region command first", provider)
				}
				region = currentRegion
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
			// 根据provider更新对应的配置
			switch provider {
			case "aliyun":
				cfg.Aliyun.CurrentInstance = instanceID
			case "volcengine":
				cfg.Volcengine.CurrentInstance = instanceID
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
			var currentProviderConfig *ProviderConfig
			switch provider {
			case providers.ALIYUN:
				currentProviderConfig = cfg.Aliyun
			case providers.VOLCENGINE:
				currentProviderConfig = cfg.Volcengine
			}
			if currentProviderConfig == nil {
				return fmt.Errorf("no provider config found for provider %s", provider)
			}
			// 从对应云服务商的配置中获取region
			if region == "" {
				if currentProviderConfig.Region != "" {
					region = currentProviderConfig.Region
				} else {
					slog.Error("no region specified or selected")
					return fmt.Errorf("no region specified or selected")
				}
			}

			if currentProviderConfig.CurrentInstance == "" {
				return fmt.Errorf("no instance selected, please use select-instance command first")
			}

			slog.Debug("Using region", "region", region)

			p, err := createProvider()
			if err != nil {
				return err
			}
			instanceProvider, ok := p.(types.InstanceProvider)
			if !ok {
				return fmt.Errorf("provider does not support instance operations")
			}
			fmt.Printf("Fetching security groups for instance %s...\n", currentProviderConfig.CurrentInstance)
			groups, err := instanceProvider.ListInstanceSecurityGroups(currentProviderConfig.CurrentInstance)
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
			var currentProviderConfig *ProviderConfig
			switch provider {
			case providers.ALIYUN:
				currentProviderConfig = cfg.Aliyun
			case providers.VOLCENGINE:
				currentProviderConfig = cfg.Volcengine
			}
			if currentProviderConfig == nil {
				return fmt.Errorf("no provider config found for provider %s", provider)
			}
			// 从对应云服务商的配置中获取region
			if region == "" {
				if currentProviderConfig.Region != "" {
					region = currentProviderConfig.Region
				} else {
					slog.Error("no region specified or selected")
					return fmt.Errorf("no region specified or selected")
				}
			}
			if secgroupID == "" {
				if currentProviderConfig.CurrentSecurityGroup != "" {
					secgroupID = currentProviderConfig.CurrentSecurityGroup
				} else {
					slog.Error("no security group specified or selected")
					return fmt.Errorf("no security group specified or selected")
				}
			}
			slog.Debug("Using region", "region", region)
			slog.Debug("Using security group", "security_group_id", secgroupID)
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
			currentProviderConfig.CurrentSecurityGroup = secgroupID
			if err := saveConfig(cfg); err != nil {
				return fmt.Errorf("save config failed: %v", err)
			}

			fmt.Printf("Current security group set to: %s (%s)\n", group.Name, group.GroupID)

			// 如果有实例被选中，显示是否关联
			if currentProviderConfig.CurrentInstance != "" {
				instanceProvider, ok := p.(types.InstanceProvider)
				if ok {
					groups, err := instanceProvider.ListInstanceSecurityGroups(currentProviderConfig.CurrentInstance)
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
		alias    string
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
			var currentProviderConfig *ProviderConfig
			switch provider {
			case providers.ALIYUN:
				currentProviderConfig = cfg.Aliyun
			case providers.VOLCENGINE:
				currentProviderConfig = cfg.Volcengine
			}
			if currentProviderConfig == nil {
				return fmt.Errorf("no provider config found for provider %s", provider)
			}

			// 从对应云服务商的配置中获取region
			if region == "" {
				if currentProviderConfig.Region != "" {
					region = currentProviderConfig.Region
				} else {
					slog.Error("no region specified or selected")
					return fmt.Errorf("no region specified or selected")
				}
			}

			// 检查安全组
			if currentProviderConfig.CurrentSecurityGroup == "" {
				return fmt.Errorf("no security group selected, please use select-secgroup command first")
			}

			// 获取本地公网IP
			ip, err := getLocalPublicIP()
			if err != nil {
				return err
			}
			ip = ip + "/32" // 转换为CIDR格式

			// 处理规则别名
			aliasDesc := "tmp"
			if alias != "" {
				if desc, ok := cfg.RuleAliases[alias]; ok {
					aliasDesc = desc
				} else {
					aliasDesc = alias
				}
			}

			p, err := createProvider()
			if err != nil {
				return err
			}

			// 如果设置了 allPorts 或未指定端口，则添加允许所有端口的规则
			if allPorts || !cmd.Flags().Changed("port") {
				port = -1
			}

			// 创建规则
			rule := types.SecurityRule{
				IP:          ip,
				Port:        port,
				Protocol:    "tcp",
				Direction:   "ingress",
				Action:      "accept",
				Priority:    1,
				Description: fmt.Sprintf("dsecgroup-%s-port-%d", aliasDesc, port),
			}

			// 如果是所有端口，更新协议和描述
			if port == -1 {
				rule.Protocol = "all"
				rule.Description = fmt.Sprintf("dsecgroup-%s-all-ports", aliasDesc)
			}

			return p.AddRule(currentProviderConfig.CurrentSecurityGroup, rule)
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 22, "Port number")
	cmd.Flags().BoolVar(&allPorts, "all-ports", false, "Allow all ports")
	cmd.Flags().StringVarP(&alias, "alias", "a", "", "Rule alias name defined in config")

	return cmd
}
