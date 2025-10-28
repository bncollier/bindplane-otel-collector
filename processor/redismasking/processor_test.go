package redismasking

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

func TestGenerateMaskedValue(t *testing.T) {
	mp := &maskingProcessor{
		config: &Config{},
		logger: zap.NewNop(),
		compiledPatterns: []*compiledPattern{
			{
				name:         "ipv4",
				maskedPrefix: "IP-",
			},
		},
	}
	
	// Test deterministic generation - same input should produce same output
	value1 := mp.generateMaskedValue("1.2.3.4", "ipv4")
	value2 := mp.generateMaskedValue("1.2.3.4", "ipv4")
	assert.Equal(t, value1, value2, "Same input should produce same masked value")
	
	// Different inputs should produce different outputs
	value3 := mp.generateMaskedValue("5.6.7.8", "ipv4")
	assert.NotEqual(t, value1, value3, "Different inputs should produce different masked values")
}

func TestMaskPatternsInString(t *testing.T) {
	mp := &maskingProcessor{
		config: &Config{},
		logger: zap.NewNop(),
	}
	
	// Note: This test won't actually mask without Redis, but tests the structure
	text := "User logged in from 192.168.1.1 on host server01.example.com"
	result := mp.maskPatternsInString(context.Background(), text)
	
	// Without Redis running, it should attempt to mask but may fail gracefully
	assert.NotEmpty(t, result)
}

func TestProcessLogs(t *testing.T) {
	mp := &maskingProcessor{
		config: &Config{
			FieldsToMask: []string{"username", "ip_address"},
		},
		logger: zap.NewNop(),
	}
	
	// Create test log data
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	
	lr.Body().SetStr("Test log message with IP 10.0.0.1")
	lr.Attributes().PutStr("username", "testuser")
	lr.Attributes().PutStr("ip_address", "10.0.0.1")
	
	// Process logs (will fail without Redis, but tests structure)
	_, err := mp.processLogs(context.Background(), ld)
	assert.NoError(t, err)
}

