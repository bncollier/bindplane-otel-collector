package redismasking

import (
	"go.opentelemetry.io/collector/component"
)

// Config defines configuration for the redis masking processor
type Config struct {
	// Redis connection settings
	RedisAddr     string `mapstructure:"redis_addr"`
	RedisPassword string `mapstructure:"redis_password"`
	RedisDB       int    `mapstructure:"redis_db"`
	
	// TTL for cached tokens in seconds (0 = no expiration)
	TokenTTL int `mapstructure:"token_ttl"`
	
	// Fields to mask - supports log attributes and body
	FieldsToMask []string `mapstructure:"fields_to_mask"`
	
	// Patterns to detect sensitive data in log body
	Patterns []PatternConfig `mapstructure:"patterns"`
}

// PatternConfig defines a pattern to detect and mask
type PatternConfig struct {
	// Name of the pattern (e.g., "ip_address", "hostname")
	Name string `mapstructure:"name"`
	
	// Regex pattern to match
	Regex string `mapstructure:"regex"`
	
	// Prefix for masked values (e.g., "IP-", "HOST-")
	MaskedPrefix string `mapstructure:"masked_prefix"`
}

var _ component.Config = (*Config)(nil)

// Validate checks if the processor configuration is valid
func (cfg *Config) Validate() error {
	if cfg.RedisAddr == "" {
		cfg.RedisAddr = "localhost:6379"
	}
	
	if cfg.TokenTTL < 0 {
		return component.NewConfigError("token_ttl must be non-negative")
	}
	
	return nil
}


