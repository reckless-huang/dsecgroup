# 云安全组管理

用于管理不同云服务提供商安全组的统一接口。

## 功能特性

- 抽象云服务提供商接口
- 支持多个云服务提供商：
  - 阿里云
  - 更多提供商即将支持...
- 资源管理：
  - 安全组（创建、删除、查询）
  - 安全组规则（添加、删除、更新、查询）
  - 实例安全组关联
  - 区域管理

## 快速开始

### 安装

```bash
go get github.com/your-username/your-project
```

### 基本用法

```go
import (
    "fmt"
    "github.com/your-username/your-project/pkg/types"
    "github.com/your-username/your-project/pkg/providers/aliyun"
)

func main() {
    // 创建阿里云提供商
    provider, err := aliyun.NewProvider(types.SecurityGroupConfig{
        Provider: "aliyun",
        Region:   "cn-beijing",
        Credential: map[string]string{
            "access_key_id":     "your-access-key",
            "access_key_secret": "your-access-secret",
        },
    })
    if err != nil {
        panic(err)
    }

    // 创建安全组
    sg, err := provider.CreateSecurityGroup("test-group", "测试安全组")
    if err != nil {
        panic(err)
    }

    // 添加安全组规则
    rule := types.SecurityRule{
        IP:          "0.0.0.0/0",
        Port:        80,
        Protocol:    "tcp",
        Direction:   "ingress",
        Action:      types.ActionAllow,
        Priority:    1,
        Description: "允许 HTTP 访问",
    }
    
    err = provider.AddRule(sg.GroupID, rule)
    if err != nil {
        panic(err)
    }
}
```

## 文档

- [英文文档](../../README.md)

## 项目结构

```
.
├── pkg/
│   ├── types/           # 接口定义和通用类型
│   └── providers/       # 云服务提供商实现
│       └── aliyun/      # 阿里云实现
├── docs/               # 文档
│   ├── en/            # 英文文档
│   └── zh/            # 中文文档
└── README.md
```

## 添加新的云服务提供商支持

1. 在 `pkg/providers` 下创建新的包
2. 实现 `types.SecurityGroupProvider` 和 `types.InstanceProvider` 接口
3. 提供配置和初始化方法

## 贡献指南

欢迎贡献！请随时提交 Pull Request。

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的更改 (`git commit -m '添加一些特性'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启一个 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 联系方式

如果您有任何问题或建议，请随时开启 issue 或 pull request。 