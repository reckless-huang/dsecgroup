# Cloud Security Group Management

A unified interface for managing security groups across different cloud providers.

## Features

- Abstract cloud provider interfaces
- Multiple cloud provider support:
  - Aliyun (Alibaba Cloud)
  - Volcengine (ByteDance Cloud)
  - More providers coming soon...
- Resource management:
  - Security Groups (create, delete, query)
  - Security Group Rules (add, remove, update, query)
  - Instance Security Group Association
  - Region Management
- Rule management features:
  - Rule aliases support
  - Batch rule deletion
  - Local IP quick-add
  - Rule description based matching

## Quick Start

### Installation

```bash
go get github.com/your-username/your-project
```

### Configuration

Create a `config.yaml` file:

```yaml
aliyun:
    access_key: "your-access-key"
    secret_key: "your-secret-key"
    region: "cn-hangzhou"
    current_instance: "i-xxx"
    current_security_group: "sg-xxx"
volcengine:
    access_key: "your-access-key"
    secret_key: "your-secret-key"
    region: "cn-beijing"
    current_instance: "i-xxx"
    current_security_group: "sg-xxx"

log:
    level: "debug"    # Options: debug, info, warn, error
    format: "text"    # Options: text, json

rule_aliases:
    home: "Home IP"
    office: "Office IP"
    tmp: "Temporary IP"
```

### Command Line Usage

```bash
# Select cloud provider
dsecgroup --provider aliyun ...
dsecgroup --provider volcengine ...

# List regions and select one
dsecgroup list-regions
dsecgroup select-region -r cn-beijing

# List instances and select one
dsecgroup list-instances
dsecgroup select-instance -i i-xxx

# List security groups and select one
dsecgroup list-secgroups
dsecgroup select-secgroup -g sg-xxx

# Quick add local IP
dsecgroup quick-add-local --port 22 --alias home
dsecgroup quick-add-local --all-ports --alias office

# Add specific rule
dsecgroup add-secgroup-rule --ip 1.2.3.4/32 --port 80
dsecgroup add-secgroup-rule --ip 1.2.3.4/32 --port -1  # all ports

# Remove rules
dsecgroup remove-secgroup-rule -i rule-id-1,rule-id-2  # Remove by rule IDs
dsecgroup remove-secgroup-rule --alias home            # Remove by alias
```

### Programmatic Usage

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

    // Add rule with description
    rule := types.SecurityRule{
        IP:          "0.0.0.0/0",
        Port:        80,
        Protocol:    "tcp",
        Direction:   "ingress",
        Action:      types.ActionAllow,
        Priority:    1,
        Description: "gen_by_dsecgroup (web server)",
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
├── cmd/
│   └── dsecgroup/     # Command line tool
├── pkg/
│   ├── types/         # Interface definitions and common types
│   └── providers/     # Cloud provider implementations
│       └── aliyun/    # Alibaba Cloud implementation
├── docs/             # Documentation
└── README.md
```

## Features in Detail

### Rule Aliases
Define meaningful aliases for your IP rules in config.yaml. When adding or removing rules, use these aliases instead of remembering IPs.

### Batch Operations
Support batch operations for rule management:
- Remove multiple rules by IDs
- Remove rules by alias matching
- Quick add rules with different ports

### Local IP Management
Automatically detect and manage rules for your local public IP:
- Quick add with port specification
- Support all ports access
- Alias-based rule management

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
