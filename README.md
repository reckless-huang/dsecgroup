# Cloud Security Group Management

A unified interface for managing security groups across different cloud providers.

## Features

- Abstract cloud provider interfaces
- Multiple cloud provider support:
  - Aliyun (Alibaba Cloud)
  - More providers coming soon...
- Resource management:
  - Security Groups (create, delete, query)
  - Security Group Rules (add, remove, update, query)
  - Instance Security Group Association
  - Region Management

## Quick Start

### Installation

```bash
go get github.com/your-username/your-project
```

### Basic Usage

```go
import (
    "fmt"
    "github.com/your-username/your-project/pkg/types"
    "github.com/your-username/your-project/pkg/providers/aliyun"
)

func main() {
    // Create Aliyun Provider
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

    // Create Security Group
    sg, err := provider.CreateSecurityGroup("test-group", "test security group")
    if err != nil {
        panic(err)
    }

    // Add Security Group Rule
    rule := types.SecurityRule{
        IP:          "0.0.0.0/0",
        Port:        80,
        Protocol:    "tcp",
        Direction:   "ingress",
        Action:      types.ActionAllow,
        Priority:    1,
        Description: "Allow HTTP access",
    }
    
    err = provider.AddRule(sg.GroupID, rule)
    if err != nil {
        panic(err)
    }
}
```

## Documentation

- [中文文档](./docs/zh/README.md)

## Project Structure

```
.
├── pkg/
│   ├── types/           # Interface definitions and common types
│   └── providers/       # Cloud provider implementations
│       └── aliyun/      # Alibaba Cloud implementation
├── docs/               # Documentation
│   ├── en/            # English docs
│   └── zh/            # Chinese docs
└── README.md
```

## Adding New Cloud Provider Support

1. Create a new package under `pkg/providers`
2. Implement the `types.SecurityGroupProvider` and `types.InstanceProvider` interfaces
3. Provide configuration and initialization methods

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

If you have any questions or suggestions, please feel free to open an issue or pull request.
