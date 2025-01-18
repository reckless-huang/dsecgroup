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

	"github.com/olekukonko/tablewriter"
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
	CurrentRegion        string            `yaml:"current_region"`
	CurrentInstance      string            `yaml:"current_instance"`
	CurrentSecurityGroup string            `yaml:"current_security_group"`
	AccessKey            string            `yaml:"access_key"`
	SecretKey            string            `yaml:"secret_key"`
	Log                  LogConfig         `yaml:"log"`
	RuleAliases          map[string]string `yaml:"rule_aliases"`
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
	// 优先从命令行参数获取凭证，如果没有则从环境变量获取
	ak := accessKey
	sk := secretKey

	// 如果命令行参数没有提供，则从配置文件获取
	if ak == "" || sk == "" {
		cfg, err := loadConfig()
		if err != nil {
			return nil, fmt.Errorf("load config failed: %v", err)
		}
		ak = cfg.AccessKey
		sk = cfg.SecretKey
	}

	// 如果配置文件也没有提供，则从环境变量获取
	if ak == "" || sk == "" {
		ak = os.Getenv("ALICLOUD_ACCESS_KEY")
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
			if cfg.CurrentRegion == "" {
				return fmt.Errorf("current region is not set")
			} else {
				region = cfg.CurrentRegion
				fmt.Printf("Current region: %s\n", cfg.CurrentRegion)
			}
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
				Protocol:  "ALL",
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

			// 设置region
			if cfg.CurrentRegion == "" {
				return fmt.Errorf("no region selected, please use select-region command first")
			}
			region = cfg.CurrentRegion
			slog.Debug("Using region", "region", region)

			// 如果未指定安全组ID，使用当前选择的安全组
			if secgroupID == "" {
				if cfg.CurrentSecurityGroup == "" {
					return fmt.Errorf("no security group specified or selected")
				}
				secgroupID = cfg.CurrentSecurityGroup
			}

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
			if cfg.CurrentSecurityGroup == "" {
				return fmt.Errorf("no security group selected, please use select-secgroup command first")
			}
			if cfg.CurrentRegion == "" {
				return fmt.Errorf("no region selected, please use select-region command first")
			}

			// 设置全局 region 变量
			region = cfg.CurrentRegion
			slog.Debug("Using region", "region", region)

			// 获取本地公网IP
			ip, err := getLocalPublicIP()
			if err != nil {
				return err
			}
			ip = ip + "/32" // 转换为CIDR格式

			// 处理规则别名
			aliasDesc := "临时IP"
			if alias != "" {
				if desc, ok := cfg.RuleAliases[alias]; ok {
					aliasDesc = desc
					slog.Debug("Using alias description", "alias", alias, "desc", aliasDesc)
				} else {
					slog.Warn("Alias not found in config, using alias as description", "alias", alias)
					aliasDesc = alias
				}
			} else {
				if desc, ok := cfg.RuleAliases["default"]; ok {
					aliasDesc = desc
				}
			}

			p, err := createProvider()
			if err != nil {
				return err
			}

			// 修改这部分逻辑：如果没有指定端口或设置了 allPorts，则添加允许所有端口的规则
			if allPorts || !cmd.Flags().Changed("port") {
				return addOrUpdateRule(p, cfg.CurrentSecurityGroup, ip, -1, fmt.Sprintf("gen_by_dsecgroup (%s, all ports)", aliasDesc))
			}

			// 添加指定端口的规则
			return addOrUpdateRule(p, cfg.CurrentSecurityGroup, ip, port, fmt.Sprintf("gen_by_dsecgroup (%s, port %d)", aliasDesc, port))
		},
	}

	// 修改默认端口的帮助文本，使其更清晰
	cmd.Flags().IntVarP(&port, "port", "p", 22, "Specific port number to allow access (if not specified, all ports will be allowed)")
	cmd.Flags().BoolVar(&allPorts, "all-ports", false, "Allow access to all ports")
	cmd.Flags().StringVarP(&alias, "alias", "a", "", "Rule alias name defined in config")
	return cmd
}

// 添加或更新规则的通用函数
func addOrUpdateRule(p types.SecurityGroupProvider, secGroupID, ip string, port int, desc string) error {
	rule := types.SecurityRule{
		IP:          ip,
		Port:        port,
		Protocol:    "tcp",
		Direction:   "ingress",
		Action:      types.ActionAllow,
		Priority:    1,
		Description: desc,
	}

	// 如果是所有端口，则使用 all 协议
	if port == -1 {
		rule.Protocol = "all"
	}

	// 检查规则是否存在
	rules, err := p.ListRules(secGroupID)
	if err != nil {
		return err
	}

	matchRules := []types.SecurityRule{}
	if hasher, ok := p.(types.RuleHasher); ok {
		slog.Debug("desc", "desc", desc)
		for _, existing := range rules {
			slog.Debug("existing rule", "rule", existing.Description)
			if existing.Description == desc {
				matchRules = append(matchRules, existing)
			}
			if hasher.IsRuleEqual(existing, rule) {
				slog.Info("Rule already exists for IP %s", "ip", ip)
				return nil
			}
		}
	}

	if len(matchRules) > 1 {
		slog.Error("Found multiple rules with the same description", "desc", desc)
		slog.Error("Rules", "rules", matchRules)
		slog.Error("run remove-secgroup-rule to remove the existing rule")
		return fmt.Errorf("found multiple rules with the same description: %v", matchRules)
	}

	create := len(matchRules) == 0
	if create {
		slog.Info("No rule found with the same description, creating new rule", "desc", desc)
		if err := p.AddRule(secGroupID, rule); err != nil {
			return fmt.Errorf("add rule failed: %v", err)
		}
	} else {
		rule = matchRules[0]
		if err := p.UpdateRule(secGroupID, rule.RuleHash, rule); err != nil {
			return fmt.Errorf("update rule failed: %v", err)
		}
	}

	fmt.Printf("Successfully applied rule for IP %s on port %d\n", ip, port)
	return nil
}
