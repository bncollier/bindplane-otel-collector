package redismasking

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

type maskingProcessor struct {
	config       *Config
	logger       *zap.Logger
	redisClient  *redis.Client
	compiledPatterns []*compiledPattern
}

type compiledPattern struct {
	name         string
	regex        *regexp.Regexp
	maskedPrefix string
}

func newMaskingProcessor(config *Config, logger *zap.Logger) (*maskingProcessor, error) {
	// Compile regex patterns
	compiledPatterns := make([]*compiledPattern, 0, len(config.Patterns))
	for _, pattern := range config.Patterns {
		regex, err := regexp.Compile(pattern.Regex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex pattern '%s': %w", pattern.Name, err)
		}
		compiledPatterns = append(compiledPatterns, &compiledPattern{
			name:         pattern.Name,
			regex:        regex,
			maskedPrefix: pattern.MaskedPrefix,
		})
	}
	
	return &maskingProcessor{
		config:           config,
		logger:           logger,
		compiledPatterns: compiledPatterns,
	}, nil
}

func (mp *maskingProcessor) start(ctx context.Context, host component.Host) error {
	// Initialize Redis client
	mp.redisClient = redis.NewClient(&redis.Options{
		Addr:     mp.config.RedisAddr,
		Password: mp.config.RedisPassword,
		DB:       mp.config.RedisDB,
	})
	
	// Test connection
	_, err := mp.redisClient.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	
	mp.logger.Info("Connected to Redis successfully", zap.String("addr", mp.config.RedisAddr))
	return nil
}

func (mp *maskingProcessor) shutdown(ctx context.Context) error {
	if mp.redisClient != nil {
		return mp.redisClient.Close()
	}
	return nil
}

func (mp *maskingProcessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				lr := sl.LogRecords().At(k)
				if err := mp.maskLogRecord(ctx, lr); err != nil {
					mp.logger.Error("Failed to mask log record", zap.Error(err))
				}
			}
		}
	}
	return ld, nil
}

func (mp *maskingProcessor) maskLogRecord(ctx context.Context, lr plog.LogRecord) error {
	// Mask specific attributes
	lr.Attributes().Range(func(k string, v pcommon.Value) bool {
		for _, fieldToMask := range mp.config.FieldsToMask {
			if k == fieldToMask {
				maskedValue, err := mp.getMaskedValue(ctx, v.AsString(), "attribute_"+k)
				if err != nil {
					mp.logger.Error("Failed to mask attribute", zap.String("key", k), zap.Error(err))
				} else {
					v.SetStr(maskedValue)
				}
			}
		}
		return true
	})
	
	// Mask patterns in log body
	if lr.Body().Type() == pcommon.ValueTypeStr {
		originalBody := lr.Body().Str()
		maskedBody := mp.maskPatternsInString(ctx, originalBody)
		if maskedBody != originalBody {
			lr.Body().SetStr(maskedBody)
		}
	}
	
	return nil
}

func (mp *maskingProcessor) maskPatternsInString(ctx context.Context, text string) string {
	result := text
	for _, pattern := range mp.compiledPatterns {
		matches := pattern.regex.FindAllString(result, -1)
		for _, match := range matches {
			maskedValue, err := mp.getMaskedValue(ctx, match, pattern.name)
			if err != nil {
				mp.logger.Error("Failed to mask value", 
					zap.String("pattern", pattern.name), 
					zap.String("value", match),
					zap.Error(err))
				continue
			}
			result = regexp.MustCompile(regexp.QuoteMeta(match)).ReplaceAllString(result, maskedValue)
		}
	}
	return result
}

func (mp *maskingProcessor) getMaskedValue(ctx context.Context, originalValue, category string) (string, error) {
	// Create a unique key for Redis
	redisKey := fmt.Sprintf("mask:%s:%s", category, originalValue)
	
	// Check if masked value already exists in Redis
	cachedValue, err := mp.redisClient.Get(ctx, redisKey).Result()
	if err == nil {
		// Found in cache, return it
		return cachedValue, nil
	} else if err != redis.Nil {
		// Real error occurred
		return "", fmt.Errorf("redis get error: %w", err)
	}
	
	// Not in cache, generate new masked value
	maskedValue := mp.generateMaskedValue(originalValue, category)
	
	// Store in Redis
	ttl := time.Duration(0)
	if mp.config.TokenTTL > 0 {
		ttl = time.Duration(mp.config.TokenTTL) * time.Second
	}
	
	err = mp.redisClient.Set(ctx, redisKey, maskedValue, ttl).Err()
	if err != nil {
		mp.logger.Error("Failed to store masked value in Redis", zap.Error(err))
		// Continue anyway, we'll use the generated value
	}
	
	// Also store reverse mapping for lookups
	reverseKey := fmt.Sprintf("unmask:%s:%s", category, maskedValue)
	_ = mp.redisClient.Set(ctx, reverseKey, originalValue, ttl)
	
	return maskedValue, nil
}

func (mp *maskingProcessor) generateMaskedValue(originalValue, category string) string {
	// Generate deterministic hash
	hash := sha256.Sum256([]byte(originalValue + category))
	hashStr := hex.EncodeToString(hash[:])
	
	// Create masked value based on category
	// For IP addresses, generate a fake IP format
	if category == "ipv4" {
		return fmt.Sprintf("10.%d.%d.%d",
			hash[0]%256,
			hash[1]%256,
			hash[2]%256,
		)
	}
	
	// For hostnames, generate a fake hostname
	if category == "hostname" {
		return fmt.Sprintf("host-%s.masked.local", hashStr[:8])
	}
	
	// For other fields, use prefix + hash
	prefix := ""
	for _, pattern := range mp.compiledPatterns {
		if pattern.name == category {
			prefix = pattern.maskedPrefix
			break
		}
	}
	
	// Extract category from attribute fields
	if len(category) > 10 && category[:10] == "attribute_" {
		prefix = category[10:] + "-"
	}
	
	return fmt.Sprintf("%s%s", prefix, hashStr[:12])
}

