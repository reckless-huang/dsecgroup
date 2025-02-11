package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reckless-huang/dsecgroup/pkg/providers"
	"github.com/reckless-huang/dsecgroup/pkg/providers/aliyun"
	"github.com/reckless-huang/dsecgroup/pkg/providers/volcengine"
	"github.com/reckless-huang/dsecgroup/pkg/types"
	"gopkg.in/yaml.v2"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

type CloudConfig struct {
	AccessKey            string `yaml:"access_key"`
	SecretKey            string `yaml:"secret_key"`
	Region               string `yaml:"region"`
	CurrentInstance      string `yaml:"current_instance"`
	CurrentSecurityGroup string `yaml:"current_security_group"`
}

type Config struct {
	Providers       map[string]CloudConfig `yaml:"providers"`
	Log             map[string]string      `yaml:"log"`
	RuleAliases     map[string]string      `yaml:"rule_aliases"`
	CurrentProvider string                 `yaml:"current_provider"`
}

func loadConfig() (*Config, error) {
	config := &Config{
		Log:         make(map[string]string),
		RuleAliases: make(map[string]string),
	}
	configFile, err := os.ReadFile("config-ui.yaml")
	if err != nil {
		return config, nil
	}
	err = yaml.Unmarshal(configFile, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func saveConfig(config *Config) error {
	// 先读取现有配置以获取CurrentProvider
	existingConfig, err := loadConfig()
	if err == nil && existingConfig.CurrentProvider != "" {
		config.CurrentProvider = existingConfig.CurrentProvider
	}

	configData, err := yaml.Marshal(config)
	if err != nil {
		fmt.Printf("配置数据序列化失败: %v\n", err)
		return err
	}

	// 使用固定的配置文件路径
	configPath := "/Users/reckless/code/DSecGroup/config-ui.yaml"
	fmt.Printf("正在保存配置到文件: %s\n", configPath)
	fmt.Printf("配置数据内容:\n%s\n", string(configData))

	// 确保配置文件目录存在
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		fmt.Printf("创建配置文件目录失败: %v\n", err)
		return err
	}

	err = os.WriteFile(configPath, configData, 0644)
	if err != nil {
		fmt.Printf("配置文件写入失败: %v\n", err)
		return err
	}
	fmt.Printf("配置文件保存成功\n")
	return nil
}

type ConfigStep int

const (
	StepBasic ConfigStep = iota
	StepRegion
	StepInstance
	StepSecurityGroup
)

func createProviderForm(name string, config CloudConfig, step ConfigStep) (*widget.Form, map[string]*widget.Entry) {
	form := &widget.Form{}
	entries := make(map[string]*widget.Entry)

	switch step {
	case StepBasic:
		entries["accessKey"] = widget.NewEntry()
		entries["accessKey"].SetText(config.AccessKey)
		entries["secretKey"] = widget.NewEntry()
		entries["secretKey"].SetText(config.SecretKey)
		form.Append("Access Key", entries["accessKey"])
		form.Append("Secret Key", entries["secretKey"])

	case StepRegion:
		// 创建Provider实例获取地域列表
		fmt.Printf("开始为%s创建Provider实例以获取地域列表\n", name)
		p, err := createProvider(name, config)
		if err != nil {
			fmt.Printf("创建Provider失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取地域列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return form, entries
		}

		fmt.Printf("开始获取地域列表\n")
		regions, err := p.ListRegions()
		if err != nil {
			fmt.Printf("获取地域列表失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取地域列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return form, entries
		}
		fmt.Printf("成功获取地域列表，共%d个地域\n", len(regions))

		// 构建地域选项列表
		fmt.Printf("开始构建地域选项列表\n")
		regionOptions := make([]string, len(regions))
		for i, r := range regions {
			regionOptions[i] = r.RegionID
			fmt.Printf("添加地域选项: %s\n", r.RegionID)
		}

		regionSelect := widget.NewSelect(regionOptions, func(selected string) {
			config.Region = selected
		})
		regionSelect.SetSelected(config.Region)
		form.Append("Region", regionSelect)

	case StepInstance:
		// 创建Provider实例获取实例列表
		fmt.Printf("开始为%s创建Provider实例以获取实例列表\n", name)
		p, err := createProvider(name, config)
		if err != nil {
			fmt.Printf("创建Provider失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取实例列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return form, entries
		}

		// 获取实例列表
		fmt.Printf("开始获取实例列表\n")
		instanceProvider, ok := p.(types.InstanceProvider)
		if !ok {
			fmt.Printf("Provider不支持实例操作\n")
			dialog.ShowError(fmt.Errorf("当前云服务商不支持实例操作"), fyne.CurrentApp().Driver().AllWindows()[0])
			return form, entries
		}

		instances, err := instanceProvider.ListInstances()
		if err != nil {
			fmt.Printf("获取实例列表失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取实例列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return form, entries
		}
		fmt.Printf("成功获取实例列表，共%d个实例\n", len(instances))

		// 构建实例选项列表
		fmt.Printf("开始构建实例选项列表\n")
		instanceOptions := make([]string, len(instances))
		for i, inst := range instances {
			instanceOptions[i] = inst.InstanceID
			fmt.Printf("添加实例选项: %s\n", inst.InstanceID)
		}

		instanceSelect := widget.NewSelect(instanceOptions, func(selected string) {
			config.CurrentInstance = selected
		})
		instanceSelect.SetSelected(config.CurrentInstance)
		form.Append("Instance", instanceSelect)

	case StepSecurityGroup:
		// 创建Provider实例获取安全组列表
		fmt.Printf("开始为%s创建Provider实例以获取安全组列表\n", name)
		p, err := createProvider(name, config)
		if err != nil {
			fmt.Printf("创建Provider失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取安全组列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return form, entries
		}

		// 获取安全组列表
		fmt.Printf("开始获取安全组列表\n")
		sgProvider, ok := p.(types.SecurityGroupProvider)
		if !ok {
			fmt.Printf("Provider不支持安全组操作\n")
			dialog.ShowError(fmt.Errorf("当前云服务商不支持安全组操作"), fyne.CurrentApp().Driver().AllWindows()[0])
			return form, entries
		}

		securityGroups, err := sgProvider.ListSecurityGroups()
		if err != nil {
			fmt.Printf("获取安全组列表失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取安全组列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return form, entries
		}
		fmt.Printf("成功获取安全组列表，共%d个安全组\n", len(securityGroups))

		// 构建安全组选项列表
		fmt.Printf("开始构建安全组选项列表\n")
		sgOptions := make([]string, len(securityGroups))
		for i, sg := range securityGroups {
			sgOptions[i] = sg.GroupID
			fmt.Printf("添加安全组选项: %s\n", sg.GroupID)
		}

		sgSelect := widget.NewSelect(sgOptions, func(selected string) {
			// 更新当前安全组配置
			config.CurrentSecurityGroup = selected
			// 保存配置以确保更改立即生效
			if err := saveConfig(&Config{
				Providers: map[string]CloudConfig{
					name: config,
				},
			}); err != nil {
				fmt.Printf("保存安全组配置失败: %v\n", err)
				dialog.ShowError(fmt.Errorf("保存安全组配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
				return
			}
			fmt.Printf("成功更新安全组配置: %s\n", selected)
		})
		sgSelect.SetSelected(config.CurrentSecurityGroup)
		form.Append("Security Group", sgSelect)
	}

	return form, entries
}

func createSettingsTab() *fyne.Container {
	config, err := loadConfig()
	if err != nil {
		config = &Config{
			Log:         make(map[string]string),
			RuleAliases: make(map[string]string),
			Providers:   make(map[string]CloudConfig),
		}
	}

	// 创建一个垂直布局容器来存放所有云服务商的配置
	providersContainer := container.NewVBox()
	formEntries := make(map[string]map[string]*widget.Entry)

	// 为每个已配置的云服务商创建配置表单
	for name, providerConfig := range config.Providers {
		providerLabel := widget.NewLabelWithStyle(name+"配置", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		form, entries := createProviderForm(name, providerConfig, StepBasic)
		formEntries[name] = entries

		// 创建删除按钮，使用闭包捕获当前的name值
		currentName := name
		deleteButton := widget.NewButton("删除", func() {
			dialog.ShowConfirm("删除确认", "确定要删除"+currentName+"配置吗？", func(confirm bool) {
				if confirm {
					delete(config.Providers, currentName)
					if err := saveConfig(config); err != nil {
						dialog.ShowError(fmt.Errorf("删除配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
						return
					}
					// 遍历providersContainer的子组件找到对应的组件并移除
					for i := 0; i < len(providersContainer.Objects); i++ {
						if hBox, ok := providersContainer.Objects[i].(*fyne.Container); ok {
							if label, ok := hBox.Objects[0].(*widget.Label); ok && label.Text == currentName+"配置" {
								// 移除header和form（form在下一个索引位置）
								providersContainer.Objects = append(providersContainer.Objects[:i], providersContainer.Objects[i+2:]...)
								break
							}
						}
					}
					delete(formEntries, currentName)
					providersContainer.Refresh()
				}
			}, fyne.CurrentApp().Driver().AllWindows()[0])
		})

		headerContainer := container.NewHBox(providerLabel, deleteButton)
		providersContainer.Add(headerContainer)
		providersContainer.Add(form)
	}

	// 添加云服务商按钮
	addProviderButton := widget.NewButton("添加云服务商", func() {
		// 创建输入对话框
		nameEntry := widget.NewEntry()
		nameEntry.SetPlaceHolder("请输入云服务商名称")
		dialog.ShowForm("添加云服务商",
			"确定",
			"取消",
			[]*widget.FormItem{
				widget.NewFormItem("名称", nameEntry),
			},
			func(confirm bool) {
				if confirm && nameEntry.Text != "" {
					name := nameEntry.Text
					// 添加新的云服务商配置表单
					providerLabel := widget.NewLabelWithStyle(name+"配置", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
					form, entries := createProviderForm(name, CloudConfig{}, StepBasic)
					formEntries[name] = entries

					// 创建下一步按钮
					nextButton := widget.NewButton("下一步", func() {
						// 保存基础配置
						config.Providers[name] = CloudConfig{
							AccessKey: entries["accessKey"].Text,
							SecretKey: entries["secretKey"].Text,
						}
						if err := saveConfig(config); err != nil {
							dialog.ShowError(fmt.Errorf("保存配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
							return
						}

						// 进入区域选择步骤
						form, entries = createProviderForm(name, config.Providers[name], StepRegion)
						formEntries[name] = entries

						// 创建区域选择的下一步按钮
						regionNextButton := widget.NewButton("下一步", func() {
							// 保存区域配置
							config.Providers[name] = CloudConfig{
								AccessKey: config.Providers[name].AccessKey,
								SecretKey: config.Providers[name].SecretKey,
								Region:    config.Providers[name].Region,
							}
							if err := saveConfig(config); err != nil {
								dialog.ShowError(fmt.Errorf("保存配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
								return
							}

							// 进入实例选择步骤
							form, entries = createProviderForm(name, config.Providers[name], StepInstance)
							formEntries[name] = entries

							// 创建实例选择的下一步按钮
							instanceNextButton := widget.NewButton("下一步", func() {
								// 保存实例配置
								config.Providers[name] = CloudConfig{
									AccessKey:       config.Providers[name].AccessKey,
									SecretKey:       config.Providers[name].SecretKey,
									Region:          config.Providers[name].Region,
									CurrentInstance: config.Providers[name].CurrentInstance,
								}
								if err := saveConfig(config); err != nil {
									dialog.ShowError(fmt.Errorf("保存配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
									return
								}

								// 进入安全组选择步骤
								form, entries = createProviderForm(name, config.Providers[name], StepSecurityGroup)
								formEntries[name] = entries

								// 创建完成按钮
								finishButton := widget.NewButton("完成", func() {
									// 保存最终配置
									config.Providers[name] = CloudConfig{
										AccessKey:            config.Providers[name].AccessKey,
										SecretKey:            config.Providers[name].SecretKey,
										Region:               config.Providers[name].Region,
										CurrentInstance:      config.Providers[name].CurrentInstance,
										CurrentSecurityGroup: config.Providers[name].CurrentSecurityGroup,
									}
									if err := saveConfig(config); err != nil {
										dialog.ShowError(fmt.Errorf("保存配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
										return
									}
									dialog.ShowInformation("成功", "云服务商配置已完成", fyne.CurrentApp().Driver().AllWindows()[0])
								})
								form.OnSubmit = finishButton.OnTapped
							})
							form.OnSubmit = instanceNextButton.OnTapped
						})
						form.OnSubmit = regionNextButton.OnTapped
					})
					form.OnSubmit = nextButton.OnTapped

					// 创建删除按钮，使用闭包捕获当前的name值
					currentName := name
					deleteButton := widget.NewButton("删除", func() {
						if providersContainer == nil {
							dialog.ShowError(fmt.Errorf("界面组件未初始化"), fyne.CurrentApp().Driver().AllWindows()[0])
							return
						}

						dialog.ShowConfirm("删除确认", "确定要删除"+currentName+"配置吗？", func(confirm bool) {
							if !confirm {
								return
							}

							// 删除配置数据
							if config != nil && config.Providers != nil {
								delete(config.Providers, currentName)
								if err := saveConfig(config); err != nil {
									dialog.ShowError(fmt.Errorf("删除配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
									return
								}
							}

							// 清空表单数据
							if formEntries != nil {
								if entries, exists := formEntries[currentName]; exists && entries != nil {
									for _, entry := range entries {
										if entry != nil {
											entry.SetText("")
										}
									}
									delete(formEntries, currentName)
								}
							}

							// 从界面移除组件
							objectsToRemove := make([]int, 0)
							for i := 0; i < len(providersContainer.Objects); i++ {
								if hBox, ok := providersContainer.Objects[i].(*fyne.Container); ok && hBox != nil {
									if label, ok := hBox.Objects[0].(*widget.Label); ok && label != nil && label.Text == currentName+"配置" {
										objectsToRemove = append(objectsToRemove, i)
										if i+1 < len(providersContainer.Objects) {
											objectsToRemove = append(objectsToRemove, i+1)
										}
										break
									}
								}
							}

							// 从后往前删除，避免索引变化的问题
							for i := len(objectsToRemove) - 1; i >= 0; i-- {
								if index := objectsToRemove[i]; index < len(providersContainer.Objects) {
									providersContainer.Remove(providersContainer.Objects[index])
								}
							}

							providersContainer.Refresh()
						}, fyne.CurrentApp().Driver().AllWindows()[0])
					})

					// 创建头部容器并添加组件
					headerContainer := container.NewHBox(providerLabel, deleteButton)
					providersContainer.Add(headerContainer)
					providersContainer.Add(form)
					providersContainer.Refresh()
				}
			},
			fyne.CurrentApp().Driver().AllWindows()[0],
		)
	})

	// 保存按钮
	saveButton := widget.NewButton("保存配置", func() {
		// 更新配置
		for name, entries := range formEntries {
			// 获取或创建配置
			providerConfig, exists := config.Providers[name]
			if !exists {
				providerConfig = CloudConfig{}
			}

			// 只更新当前存在的表单项，保留其他配置
			for key, entry := range entries {
				switch key {
				case "accessKey":
					providerConfig.AccessKey = entry.Text
				case "secretKey":
					providerConfig.SecretKey = entry.Text
				}
			}

			// 更新配置，保留原有的其他字段
			if exists {
				oldConfig := config.Providers[name]
				if providerConfig.Region == "" {
					providerConfig.Region = oldConfig.Region
				}
				if providerConfig.CurrentInstance == "" {
					providerConfig.CurrentInstance = oldConfig.CurrentInstance
				}
				if providerConfig.CurrentSecurityGroup == "" {
					providerConfig.CurrentSecurityGroup = oldConfig.CurrentSecurityGroup
				}
			}
			config.Providers[name] = providerConfig
		}

		if err := saveConfig(config); err != nil {
			dialog.ShowError(fmt.Errorf("保存配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		dialog.ShowInformation("成功", "配置已保存", fyne.CurrentApp().Driver().AllWindows()[0])
	})

	// 创建一个垂直布局的主容器
	mainContainer := container.NewVBox(
		addProviderButton,
		providersContainer,
		saveButton,
	)

	return mainContainer
}

var currentProvider string

func createProviderSelector(config *Config, tabs *container.AppTabs) *widget.Select {
	providerNames := make([]string, 0, len(config.Providers))
	for name := range config.Providers {
		providerNames = append(providerNames, name)
	}

	providerSelect := widget.NewSelect(providerNames, func(selected string) {
		currentProvider = selected
		config.CurrentProvider = selected
		if err := saveConfig(config); err != nil {
			fmt.Printf("保存当前云服务商配置失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("保存当前云服务商配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
		}
		fmt.Printf("当前选择的云服务商: %s\n", selected)
		// 更新操作面板
		if len(tabs.Items) > 1 {
			tabs.Items[1].Content = createOperationPanel(config)
			tabs.Refresh()
		}
	})

	// 优先使用上次保存的云服务商
	if config.CurrentProvider != "" && len(config.Providers) > 0 && config.Providers[config.CurrentProvider] != (CloudConfig{}) {
		providerSelect.SetSelected(config.CurrentProvider)
		currentProvider = config.CurrentProvider
	} else if len(providerNames) > 0 {
		providerSelect.SetSelected(providerNames[0])
		currentProvider = providerNames[0]
	}

	return providerSelect
}

func createOperationPanel(config *Config) fyne.CanvasObject {
	fmt.Printf("开始创建操作面板，当前Provider: %s\n", currentProvider)
	providerConfig, exists := config.Providers[currentProvider]
	if !exists {
		fmt.Printf("未找到Provider配置: %s\n", currentProvider)
		return widget.NewLabel("请先选择云服务商")
	}

	// 创建四个主要功能按钮
	selectRegionBtn := widget.NewButton(fmt.Sprintf("选择地域 (当前: %s)", providerConfig.Region), func() {
		fmt.Printf("点击选择地域按钮，当前Provider: %s\n", currentProvider)
		// 创建Provider实例获取地域列表
		p, err := createProvider(currentProvider, providerConfig)
		if err != nil {
			fmt.Printf("创建Provider失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取地域列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		fmt.Printf("成功创建Provider实例\n")

		// 获取地域列表
		fmt.Printf("开始获取地域列表\n")
		regions, err := p.ListRegions()
		if err != nil {
			fmt.Printf("获取地域列表失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取地域列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		fmt.Printf("成功获取地域列表，共%d个地域\n", len(regions))

		// 构建地域选项列表
		regionOptions := make([]string, len(regions))
		for i, r := range regions {
			regionOptions[i] = r.RegionID
			fmt.Printf("添加地域选项: %s\n", r.RegionID)
		}

		regionSelect := widget.NewSelect(regionOptions, func(selected string) {
			fmt.Printf("选择地域: %s\n", selected)
			providerConfig.Region = selected
			config.Providers[currentProvider] = providerConfig
			if err := saveConfig(config); err != nil {
				fmt.Printf("保存地域配置失败: %v\n", err)
				dialog.ShowError(fmt.Errorf("保存地域配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			} else {
				fmt.Printf("成功保存地域配置\n")
			}
		})
		regionSelect.SetSelected(providerConfig.Region)
		dialog.ShowCustom("选择地域", "确定", regionSelect, fyne.CurrentApp().Driver().AllWindows()[0])
	})

	selectInstanceBtn := widget.NewButton(fmt.Sprintf("选择服务器 (当前: %s)", providerConfig.CurrentInstance), func() {
		fmt.Printf("点击选择服务器按钮，当前Provider: %s\n", currentProvider)
		// 创建Provider实例获取实例列表
		p, err := createProvider(currentProvider, providerConfig)
		if err != nil {
			fmt.Printf("创建Provider失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取实例列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		fmt.Printf("成功创建Provider实例\n")

		// 获取实例列表
		fmt.Printf("开始获取实例列表\n")
		instanceProvider, ok := p.(types.InstanceProvider)
		if !ok {
			fmt.Printf("Provider不支持实例操作\n")
			dialog.ShowError(fmt.Errorf("当前云服务商不支持实例操作"), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}

		instances, err := instanceProvider.ListInstances()
		if err != nil {
			fmt.Printf("获取实例列表失败: %v\n", err)
			dialog.ShowError(fmt.Errorf("获取实例列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		fmt.Printf("成功获取实例列表，共%d个实例\n", len(instances))

		// 构建实例选项列表
		instanceOptions := make([]string, len(instances))
		for i, inst := range instances {
			instanceOptions[i] = inst.InstanceID
			fmt.Printf("添加实例选项: %s\n", inst.InstanceID)
		}

		instanceSelect := widget.NewSelect(instanceOptions, func(selected string) {
			fmt.Printf("选择实例: %s\n", selected)
			providerConfig.CurrentInstance = selected
			config.Providers[currentProvider] = providerConfig
			if err := saveConfig(config); err != nil {
				fmt.Printf("保存实例配置失败: %v\n", err)
				dialog.ShowError(fmt.Errorf("保存实例配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			} else {
				fmt.Printf("成功保存实例配置\n")
			}
		})
		instanceSelect.SetSelected(providerConfig.CurrentInstance)
		dialog.ShowCustom("选择服务器", "确定", instanceSelect, fyne.CurrentApp().Driver().AllWindows()[0])
	})

	selectSecurityGroupBtn := widget.NewButton(fmt.Sprintf("选择安全组 (当前: %s)", providerConfig.CurrentSecurityGroup), func() {
		provider, err := createProvider(currentProvider, config.Providers[currentProvider])
		if err != nil {
			dialog.ShowError(fmt.Errorf("创建Provider失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}

		securityGroups, err := provider.ListSecurityGroups()
		if err != nil {
			dialog.ShowError(fmt.Errorf("获取安全组列表失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}

		sgOptions := make([]string, len(securityGroups))
		for i, sg := range securityGroups {
			sgOptions[i] = sg.GroupID
		}

		sgSelect := widget.NewSelect(sgOptions, func(selected string) {
			providerConfig.CurrentSecurityGroup = selected
			config.Providers[currentProvider] = providerConfig
			if err := saveConfig(config); err != nil {
				dialog.ShowError(fmt.Errorf("保存安全组配置失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			}
		})
		sgSelect.SetSelected(providerConfig.CurrentSecurityGroup)
		dialog.ShowCustom("选择安全组", "确定", sgSelect, fyne.CurrentApp().Driver().AllWindows()[0])
	})

	addCurrentIPBtn := widget.NewButton("添加当前IP到安全组", func() {
		// 检查是否选择了安全组
		if providerConfig.CurrentSecurityGroup == "" {
			dialog.ShowError(fmt.Errorf("请先选择安全组"), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}

		// 创建Provider实例
		provider, err := createProvider(currentProvider, providerConfig)
		if err != nil {
			dialog.ShowError(fmt.Errorf("创建Provider失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}

		// 获取本地公网IP
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
			Timeout: time.Second * 10,
		}
		resp, err := client.Do(req)
		if err != nil {
			dialog.ShowError(fmt.Errorf("获取本地IP失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}
		defer resp.Body.Close()

		// 读取响应内容
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			dialog.ShowError(fmt.Errorf("读取IP失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}

		// 提取纯 IP 地址
		ip := strings.TrimSpace(string(body))

		// 验证是否是有效的 IP 地址
		if net.ParseIP(ip) == nil {
			dialog.ShowError(fmt.Errorf("获取到的IP地址无效: %s", ip), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}

		// 创建规则
		rule := types.SecurityRule{
			IP:          ip + "/32",
			Port:        -1,
			Protocol:    "all",
			Direction:   "ingress",
			Action:      "accept",
			Priority:    1,
			Description: "dsecgroup-ui-all-ports",
		}

		// 添加规则
		err = provider.AddRule(providerConfig.CurrentSecurityGroup, rule)
		if err != nil {
			dialog.ShowError(fmt.Errorf("添加规则失败: %v", err), fyne.CurrentApp().Driver().AllWindows()[0])
			return
		}

		dialog.ShowInformation("成功", fmt.Sprintf("已将本地IP %s 添加到安全组", ip), fyne.CurrentApp().Driver().AllWindows()[0])
	})

	return container.NewVBox(
		selectRegionBtn,
		selectInstanceBtn,
		selectSecurityGroupBtn,
		addCurrentIPBtn,
	)
}

func createProvider(name string, config CloudConfig) (types.SecurityGroupProvider, error) {
	fmt.Printf("开始创建Provider，名称: %s, 地域: %s\n", name, config.Region)
	providerConfig := types.SecurityGroupConfig{
		Provider: name,
		Region:   config.Region,
		Credential: map[string]string{
			"access_key_id":     config.AccessKey,
			"access_key_secret": config.SecretKey,
		},
	}

	switch name {
	case providers.ALIYUN:
		return aliyun.NewProvider(providerConfig)
	case providers.VOLCENGINE:
		providerConfig.CurrentInstanceId = config.CurrentInstance
		return volcengine.NewProvider(providerConfig)
	default:
		return nil, fmt.Errorf("不支持的云服务商: %s", name)
	}
}

func main() {
	a := app.New()
	w := a.NewWindow("DSecGroup配置")

	config, err := loadConfig()
	if err != nil {
		dialog.ShowError(fmt.Errorf("加载配置失败: %v", err), w)
		return
	}

	tabs := container.NewAppTabs(
		container.NewTabItem("设置", createSettingsTab()),
		container.NewTabItem("操作面板", widget.NewLabel("请选择云服务商")),
	)

	providerSelector := createProviderSelector(config, tabs)

	mainContainer := container.NewVBox(
		container.NewHBox(
			widget.NewLabel("当前云服务商:"),
			providerSelector,
		),
		tabs,
	)

	w.SetContent(mainContainer)
	w.Resize(fyne.NewSize(800, 600))
	w.ShowAndRun()
}
