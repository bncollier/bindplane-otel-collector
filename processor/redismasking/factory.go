package redismasking

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

const (
	typeStr   = "redismasking"
	stability = component.StabilityLevelAlpha
)

// NewFactory creates a new processor factory
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		processor.WithLogs(createLogsProcessor, stability),
	)
}

// createDefaultConfig creates the default configuration
func createDefaultConfig() component.Config {
	return &Config{
		RedisAddr:    "localhost:6379",
		RedisPassword: "",
		RedisDB:      0,
		TokenTTL:     0, // No expiration by default
		FieldsToMask: []string{},
		Patterns: []PatternConfig{
			{
				Name:         "ipv4",
				Regex:        `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
				MaskedPrefix: "IP-",
			},
			{
				Name:         "hostname",
				Regex:        `\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b`,
				MaskedPrefix: "HOST-",
			},
		},
	}
}

// createLogsProcessor creates a logs processor
func createLogsProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	nextConsumer consumer.Logs,
) (processor.Logs, error) {
	processorCfg := cfg.(*Config)
	
	mp, err := newMaskingProcessor(processorCfg, set.Logger)
	if err != nil {
		return nil, err
	}
	
	return processorhelper.NewLogsProcessor(
		ctx,
		set,
		cfg,
		nextConsumer,
		mp.processLogs,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}),
		processorhelper.WithStart(mp.start),
		processorhelper.WithShutdown(mp.shutdown),
	)
}

