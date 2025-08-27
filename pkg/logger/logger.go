package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger wraps the structured logger with additional functionality
type Logger struct {
	*slog.Logger
	config LoggerConfig
}

// LoggerConfig contains configuration for the logger
type LoggerConfig struct {
	Level      string // debug, info, warn, error
	Format     string // json, text
	Output     string // stdout, stderr, file
	File       string // log file path (if output=file)
	MaxSize    int    // max log file size in MB
	MaxBackups int    // max number of old log files
	MaxAge     int    // max number of days to retain logs
}

// DefaultLoggerConfig returns a logger configuration with sensible defaults
func DefaultLoggerConfig() LoggerConfig {
	return LoggerConfig{
		Level:      "info",
		Format:     "text",
		Output:     "stdout",
		File:       "",
		MaxSize:    100,
		MaxBackups: 3,
		MaxAge:     28,
	}
}

// NewLogger creates a new structured logger with the given configuration
func NewLogger(config LoggerConfig) (*Logger, error) {
	// Determine log level
	level, err := parseLogLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	// Determine output writer
	writer, err := getLogWriter(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create log writer: %w", err)
	}

	// Create handler based on format
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize timestamp format
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339))
			}
			return a
		},
	}

	switch strings.ToLower(config.Format) {
	case "json":
		handler = slog.NewJSONHandler(writer, opts)
	case "text":
		handler = slog.NewTextHandler(writer, opts)
	default:
		return nil, fmt.Errorf("unsupported log format: %s", config.Format)
	}

	logger := slog.New(handler)

	return &Logger{
		Logger: logger,
		config: config,
	}, nil
}

// parseLogLevel parses the string log level to slog.Level
func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %s", level)
	}
}

// getLogWriter creates an appropriate writer based on the output configuration
func getLogWriter(config LoggerConfig) (io.Writer, error) {
	switch strings.ToLower(config.Output) {
	case "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	case "file":
		if config.File == "" {
			return nil, fmt.Errorf("log file path is required when output is 'file'")
		}

		// Create directory if it doesn't exist
		dir := filepath.Dir(config.File)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Use lumberjack for log rotation
		return &lumberjack.Logger{
			Filename:   config.File,
			MaxSize:    config.MaxSize,
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge,
			Compress:   true,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported log output: %s", config.Output)
	}
}

// WithFields returns a logger with the given fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	var attrs []any
	for k, v := range fields {
		attrs = append(attrs, slog.Any(k, v))
	}

	return &Logger{
		Logger: l.Logger.With(attrs...),
		config: l.config,
	}
}

// WithField returns a logger with a single field
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.Any(key, value)),
		config: l.config,
	}
}

// WithError returns a logger with an error field
func (l *Logger) WithError(err error) *Logger {
	return l.WithField("error", err.Error())
}

// Helper methods for common logging patterns

// LogHTTPRequest logs an HTTP request with standard fields
func (l *Logger) LogHTTPRequest(method, url string, statusCode int, duration time.Duration) {
	l.Info("HTTP request",
		slog.String("method", method),
		slog.String("url", url),
		slog.Int("status_code", statusCode),
		slog.Duration("duration", duration),
	)
}

// LogCheckResult logs a status check result
func (l *Logger) LogCheckResult(url string, statusCode int, responseTime time.Duration, success bool) {
	level := slog.LevelInfo
	if !success {
		level = slog.LevelWarn
	}

	l.Log(nil, level, "Status check completed",
		slog.String("url", url),
		slog.Int("status_code", statusCode),
		slog.Duration("response_time", responseTime),
		slog.Bool("success", success),
	)
}

// LogHealthCheck logs a health check result
func (l *Logger) LogHealthCheck(service string, healthy bool, details string) {
	level := slog.LevelInfo
	if !healthy {
		level = slog.LevelWarn
	}

	l.Log(nil, level, "Health check",
		slog.String("service", service),
		slog.Bool("healthy", healthy),
		slog.String("details", details),
	)
}

// LogStartup logs application startup information
func (l *Logger) LogStartup(version, buildTime string) {
	l.Info("Application starting",
		slog.String("version", version),
		slog.String("build_time", buildTime),
		slog.String("log_level", l.config.Level),
		slog.String("log_format", l.config.Format),
	)
}

// LogShutdown logs application shutdown
func (l *Logger) LogShutdown(reason string) {
	l.Info("Application shutting down",
		slog.String("reason", reason),
	)
}

// Sync flushes any buffered log entries (useful for file outputs)
func (l *Logger) Sync() error {
	// For lumberjack logger, we don't need to do anything special
	// The underlying writer handles flushing automatically
	return nil
}
