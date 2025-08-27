package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Config represents the application configuration
type Config struct {
	// HTTP Client settings
	HTTP HTTPConfig `json:"http"`

	// Logging settings
	Logging LoggingConfig `json:"logging"`

	// Health check settings
	HealthCheck HealthCheckConfig `json:"health_check"`

	// Metrics settings
	Metrics MetricsConfig `json:"metrics"`

	// Default check settings
	Defaults DefaultsConfig `json:"defaults"`
}

// HTTPConfig contains HTTP client configuration
type HTTPConfig struct {
	Timeout               time.Duration `json:"timeout"`
	DialTimeout           time.Duration `json:"dial_timeout"`
	TLSHandshakeTimeout   time.Duration `json:"tls_handshake_timeout"`
	ResponseHeaderTimeout time.Duration `json:"response_header_timeout"`
	KeepAlive             time.Duration `json:"keep_alive"`
	MaxIdleConns          int           `json:"max_idle_conns"`
	MaxConnsPerHost       int           `json:"max_conns_per_host"`
	UserAgent             string        `json:"user_agent"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string `json:"level"`       // debug, info, warn, error
	Format     string `json:"format"`      // json, text
	Output     string `json:"output"`      // stdout, stderr, file
	File       string `json:"file"`        // log file path (if output=file)
	MaxSize    int    `json:"max_size"`    // max log file size in MB
	MaxBackups int    `json:"max_backups"` // max number of old log files
	MaxAge     int    `json:"max_age"`     // max number of days to retain logs
}

// HealthCheckConfig contains health check configuration
type HealthCheckConfig struct {
	Enabled          bool          `json:"enabled"`
	Port             int           `json:"port"`
	Path             string        `json:"path"`
	Interval         time.Duration `json:"interval"`
	Timeout          time.Duration `json:"timeout"`
	UnhealthyTimeout time.Duration `json:"unhealthy_timeout"`
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Path    string `json:"path"`
}

// DefaultsConfig contains default values for checks
type DefaultsConfig struct {
	Pings           int           `json:"pings"`
	MaxPings        int           `json:"max_pings"`
	DelayBetween    time.Duration `json:"delay_between"`
	CheckTimeout    time.Duration `json:"check_timeout"`
	FollowRedirects bool          `json:"follow_redirects"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		HTTP: HTTPConfig{
			Timeout:               10 * time.Second,
			DialTimeout:           5 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			KeepAlive:             5 * time.Second,
			MaxIdleConns:          100,
			MaxConnsPerHost:       10,
			UserAgent:             "http-status-checker/2.0",
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			Output:     "stdout",
			File:       "",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
		},
		HealthCheck: HealthCheckConfig{
			Enabled:          false,
			Port:             8080,
			Path:             "/health",
			Interval:         30 * time.Second,
			Timeout:          10 * time.Second,
			UnhealthyTimeout: 60 * time.Second,
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Port:    9090,
			Path:    "/metrics",
		},
		Defaults: DefaultsConfig{
			Pings:           4,
			MaxPings:        100,
			DelayBetween:    500 * time.Millisecond,
			CheckTimeout:    10 * time.Second,
			FollowRedirects: true,
		},
	}
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Load from file if it exists
	if configPath != "" && fileExists(configPath) {
		if err := loadFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Override with environment variables
	loadFromEnv(config)

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// SaveConfig saves the current configuration to a file
func SaveConfig(config *Config, configPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal config to JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetDefaultConfigPath returns the default configuration file path
func GetDefaultConfigPath() string {
	if configDir := os.Getenv("XDG_CONFIG_HOME"); configDir != "" {
		return filepath.Join(configDir, "http-status-checker", "config.json")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./config.json"
	}

	return filepath.Join(homeDir, ".config", "http-status-checker", "config.json")
}

// loadFromFile loads configuration from a JSON file
func loadFromFile(config *Config, configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, config)
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(config *Config) {
	// HTTP settings
	if timeout := os.Getenv("HSC_HTTP_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.HTTP.Timeout = d
		}
	}

	if userAgent := os.Getenv("HSC_USER_AGENT"); userAgent != "" {
		config.HTTP.UserAgent = userAgent
	}

	// Logging settings
	if level := os.Getenv("HSC_LOG_LEVEL"); level != "" {
		config.Logging.Level = level
	}

	if format := os.Getenv("HSC_LOG_FORMAT"); format != "" {
		config.Logging.Format = format
	}

	if output := os.Getenv("HSC_LOG_OUTPUT"); output != "" {
		config.Logging.Output = output
	}

	if file := os.Getenv("HSC_LOG_FILE"); file != "" {
		config.Logging.File = file
	}

	// Health check settings
	if enabled := os.Getenv("HSC_HEALTH_ENABLED"); enabled != "" {
		if b, err := strconv.ParseBool(enabled); err == nil {
			config.HealthCheck.Enabled = b
		}
	}

	if port := os.Getenv("HSC_HEALTH_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.HealthCheck.Port = p
		}
	}

	// Metrics settings
	if enabled := os.Getenv("HSC_METRICS_ENABLED"); enabled != "" {
		if b, err := strconv.ParseBool(enabled); err == nil {
			config.Metrics.Enabled = b
		}
	}

	if port := os.Getenv("HSC_METRICS_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.Metrics.Port = p
		}
	}

	// Default settings
	if pings := os.Getenv("HSC_DEFAULT_PINGS"); pings != "" {
		if p, err := strconv.Atoi(pings); err == nil {
			config.Defaults.Pings = p
		}
	}
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	if config.HTTP.Timeout <= 0 {
		return fmt.Errorf("HTTP timeout must be positive")
	}

	if config.Defaults.Pings <= 0 || config.Defaults.Pings > config.Defaults.MaxPings {
		return fmt.Errorf("default pings must be between 1 and %d", config.Defaults.MaxPings)
	}

	if config.HealthCheck.Enabled && (config.HealthCheck.Port <= 0 || config.HealthCheck.Port > 65535) {
		return fmt.Errorf("health check port must be between 1 and 65535")
	}

	if config.Metrics.Enabled && (config.Metrics.Port <= 0 || config.Metrics.Port > 65535) {
		return fmt.Errorf("metrics port must be between 1 and 65535")
	}

	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[config.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", config.Logging.Level)
	}

	validLogFormats := map[string]bool{"json": true, "text": true}
	if !validLogFormats[config.Logging.Format] {
		return fmt.Errorf("invalid log format: %s", config.Logging.Format)
	}

	validLogOutputs := map[string]bool{"stdout": true, "stderr": true, "file": true}
	if !validLogOutputs[config.Logging.Output] {
		return fmt.Errorf("invalid log output: %s", config.Logging.Output)
	}

	if config.Logging.Output == "file" && config.Logging.File == "" {
		return fmt.Errorf("log file path required when output is 'file'")
	}

	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
