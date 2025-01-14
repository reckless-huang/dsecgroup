package types

import "errors"

var (
	ErrInvalidConfig     = errors.New("invalid provider configuration")
	ErrProviderNotFound  = errors.New("security group provider not found")
	ErrRuleAlreadyExists = errors.New("security group rule already exists")
	ErrRuleNotFound      = errors.New("security group rule not found")
)
