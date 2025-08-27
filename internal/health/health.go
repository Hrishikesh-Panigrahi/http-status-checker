package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Hrishikesh-Panigrahi/http-status-checker/internal/checker"
)

// HealthStatus represents the health status of a service
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// ServiceType represents the type of service being checked
type ServiceType string

const (
	ServiceTypeHTTP     ServiceType = "http"
	ServiceTypeDatabase ServiceType = "database"
	ServiceTypeTCP      ServiceType = "tcp"
	ServiceTypeCustom   ServiceType = "custom"
)

// Check represents a single health check
type Check struct {
	Name        string            `json:"name"`
	Type        ServiceType       `json:"type"`
	Status      HealthStatus      `json:"status"`
	Message     string            `json:"message"`
	Duration    time.Duration     `json:"duration"`
	LastCheck   time.Time         `json:"last_check"`
	Details     map[string]string `json:"details,omitempty"`
	Error       string            `json:"error,omitempty"`
	Timeout     time.Duration     `json:"-"`
	Interval    time.Duration     `json:"-"`
	Checker     CheckerFunc       `json:"-"`
	Config      interface{}       `json:"-"`
	Enabled     bool              `json:"enabled"`
	Critical    bool              `json:"critical"`
	RetryCount  int               `json:"retry_count"`
	MaxRetries  int               `json:"max_retries"`
	LastSuccess time.Time         `json:"last_success"`
	LastFailure time.Time         `json:"last_failure"`
}

// CheckerFunc defines the function signature for health check implementations
type CheckerFunc func(ctx context.Context, config interface{}) *Check

// HealthMonitor manages and runs health checks
type HealthMonitor struct {
	checks   map[string]*Check
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
	ticker   *time.Ticker
}

// HTTPCheckConfig contains configuration for HTTP health checks
type HTTPCheckConfig struct {
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	ExpectedStatus int               `json:"expected_status"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	Timeout        time.Duration     `json:"timeout"`
}

// DatabaseCheckConfig contains configuration for database health checks
type DatabaseCheckConfig struct {
	DriverName     string        `json:"driver_name"`
	DataSourceName string        `json:"data_source_name"`
	Query          string        `json:"query"`
	Timeout        time.Duration `json:"timeout"`
}

// TCPCheckConfig contains configuration for TCP health checks
type TCPCheckConfig struct {
	Host    string        `json:"host"`
	Port    int           `json:"port"`
	Timeout time.Duration `json:"timeout"`
}

// OverallHealth represents the overall health status
type OverallHealth struct {
	Status      HealthStatus   `json:"status"`
	Message     string         `json:"message"`
	Timestamp   time.Time      `json:"timestamp"`
	Duration    time.Duration  `json:"duration"`
	Checks      []*Check       `json:"checks"`
	Summary     HealthSummary  `json:"summary"`
	Version     string         `json:"version,omitempty"`
	Environment string         `json:"environment,omitempty"`
	Uptime      time.Duration  `json:"uptime,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// HealthSummary provides a summary of health check results
type HealthSummary struct {
	Total     int `json:"total"`
	Healthy   int `json:"healthy"`
	Unhealthy int `json:"unhealthy"`
	Unknown   int `json:"unknown"`
	Critical  int `json:"critical"`
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor() *HealthMonitor {
	return &HealthMonitor{
		checks:   make(map[string]*Check),
		stopChan: make(chan struct{}),
	}
}

// AddCheck adds a health check to the monitor
func (h *HealthMonitor) AddCheck(check *Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[check.Name] = check
}

// RemoveCheck removes a health check from the monitor
func (h *HealthMonitor) RemoveCheck(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.checks, name)
}

// GetCheck returns a specific health check
func (h *HealthMonitor) GetCheck(name string) (*Check, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	check, exists := h.checks[name]
	return check, exists
}

// RunCheck executes a single health check
func (h *HealthMonitor) RunCheck(ctx context.Context, name string) *Check {
	h.mu.RLock()
	check, exists := h.checks[name]
	h.mu.RUnlock()

	if !exists || !check.Enabled {
		return &Check{
			Name:    name,
			Status:  HealthStatusUnknown,
			Message: "Check not found or disabled",
		}
	}

	// Create a timeout context
	if check.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, check.Timeout)
		defer cancel()
	}

	// Run the check
	start := time.Now()
	result := check.Checker(ctx, check.Config)
	result.Duration = time.Since(start)
	result.LastCheck = time.Now()

	// Update status in the stored check
	h.mu.Lock()
	if storedCheck, exists := h.checks[name]; exists {
		storedCheck.Status = result.Status
		storedCheck.Message = result.Message
		storedCheck.Duration = result.Duration
		storedCheck.LastCheck = result.LastCheck
		storedCheck.Error = result.Error
		storedCheck.Details = result.Details

		if result.Status == HealthStatusHealthy {
			storedCheck.LastSuccess = result.LastCheck
			storedCheck.RetryCount = 0
		} else {
			storedCheck.LastFailure = result.LastCheck
			storedCheck.RetryCount++
		}
	}
	h.mu.Unlock()

	return result
}

// RunAllChecks executes all enabled health checks
func (h *HealthMonitor) RunAllChecks(ctx context.Context) []*Check {
	h.mu.RLock()
	checks := make([]*Check, 0, len(h.checks))
	for _, check := range h.checks {
		if check.Enabled {
			checks = append(checks, check)
		}
	}
	h.mu.RUnlock()

	results := make([]*Check, len(checks))
	var wg sync.WaitGroup

	for i, check := range checks {
		wg.Add(1)
		go func(index int, checkName string) {
			defer wg.Done()
			results[index] = h.RunCheck(ctx, checkName)
		}(i, check.Name)
	}

	wg.Wait()
	return results
}

// GetOverallHealth returns the overall health status
func (h *HealthMonitor) GetOverallHealth(ctx context.Context) *OverallHealth {
	start := time.Now()
	checks := h.RunAllChecks(ctx)

	summary := HealthSummary{
		Total: len(checks),
	}

	overallStatus := HealthStatusHealthy
	var messages []string

	for _, check := range checks {
		switch check.Status {
		case HealthStatusHealthy:
			summary.Healthy++
		case HealthStatusUnhealthy:
			summary.Unhealthy++
			if check.Critical {
				summary.Critical++
				overallStatus = HealthStatusUnhealthy
				messages = append(messages, fmt.Sprintf("Critical check '%s' failed: %s", check.Name, check.Message))
			} else if overallStatus == HealthStatusHealthy {
				overallStatus = HealthStatusUnhealthy
			}
		case HealthStatusUnknown:
			summary.Unknown++
			if overallStatus == HealthStatusHealthy {
				overallStatus = HealthStatusUnknown
			}
		}
	}

	message := "All systems operational"
	if len(messages) > 0 {
		message = fmt.Sprintf("Issues detected: %v", messages)
	} else if summary.Unhealthy > 0 {
		message = fmt.Sprintf("%d non-critical checks failing", summary.Unhealthy)
	} else if summary.Unknown > 0 {
		message = fmt.Sprintf("%d checks in unknown state", summary.Unknown)
	}

	return &OverallHealth{
		Status:    overallStatus,
		Message:   message,
		Timestamp: time.Now(),
		Duration:  time.Since(start),
		Checks:    checks,
		Summary:   summary,
	}
}

// Start begins continuous health monitoring
func (h *HealthMonitor) Start(interval time.Duration) {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.running = true
	h.ticker = time.NewTicker(interval)
	h.mu.Unlock()

	go func() {
		for {
			select {
			case <-h.ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				h.RunAllChecks(ctx)
				cancel()
			case <-h.stopChan:
				return
			}
		}
	}()
}

// Stop stops the health monitor
func (h *HealthMonitor) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return
	}

	h.running = false
	if h.ticker != nil {
		h.ticker.Stop()
	}
	close(h.stopChan)
}

// HTTPHandler returns an HTTP handler for health checks
func (h *HealthMonitor) HTTPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		health := h.GetOverallHealth(ctx)

		w.Header().Set("Content-Type", "application/json")

		// Set appropriate HTTP status code
		switch health.Status {
		case HealthStatusHealthy:
			w.WriteHeader(http.StatusOK)
		case HealthStatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		if err := json.NewEncoder(w).Encode(health); err != nil {
			http.Error(w, "Failed to encode health status", http.StatusInternalServerError)
		}
	}
}

// Built-in health check implementations

// HTTPChecker creates an HTTP health check
func HTTPChecker(config HTTPCheckConfig) CheckerFunc {
	httpChecker := checker.NewHTTPChecker(checker.DefaultCheckerConfig())

	return func(ctx context.Context, cfg interface{}) *Check {
		config := cfg.(HTTPCheckConfig)

		check := &Check{
			Type:    ServiceTypeHTTP,
			Details: make(map[string]string),
		}

		result, err := httpChecker.CheckWithMethod(ctx, config.Method, config.URL)
		if err != nil {
			check.Status = HealthStatusUnhealthy
			check.Error = err.Error()
			check.Message = fmt.Sprintf("HTTP check failed: %v", err)
			return check
		}

		check.Details["url"] = config.URL
		check.Details["method"] = config.Method
		check.Details["status_code"] = fmt.Sprintf("%d", result.StatusCode)
		check.Details["response_time"] = result.ResponseTime.String()

		if config.ExpectedStatus > 0 {
			if result.StatusCode == config.ExpectedStatus {
				check.Status = HealthStatusHealthy
				check.Message = fmt.Sprintf("HTTP check passed (status: %d)", result.StatusCode)
			} else {
				check.Status = HealthStatusUnhealthy
				check.Message = fmt.Sprintf("Expected status %d, got %d", config.ExpectedStatus, result.StatusCode)
			}
		} else {
			if result.Success {
				check.Status = HealthStatusHealthy
				check.Message = fmt.Sprintf("HTTP check passed (status: %d)", result.StatusCode)
			} else {
				check.Status = HealthStatusUnhealthy
				check.Message = fmt.Sprintf("HTTP check failed (status: %d)", result.StatusCode)
			}
		}

		return check
	}
}

// DatabaseChecker creates a database health check
func DatabaseChecker(config DatabaseCheckConfig) CheckerFunc {
	return func(ctx context.Context, cfg interface{}) *Check {
		config := cfg.(DatabaseCheckConfig)

		check := &Check{
			Type:    ServiceTypeDatabase,
			Details: make(map[string]string),
		}

		// Open database connection
		db, err := sql.Open(config.DriverName, config.DataSourceName)
		if err != nil {
			check.Status = HealthStatusUnhealthy
			check.Error = err.Error()
			check.Message = fmt.Sprintf("Failed to open database: %v", err)
			return check
		}
		defer db.Close()

		// Set timeout
		if config.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, config.Timeout)
			defer cancel()
		}

		// Execute query
		query := config.Query
		if query == "" {
			query = "SELECT 1"
		}

		start := time.Now()
		_, err = db.ExecContext(ctx, query)
		queryTime := time.Since(start)

		check.Details["driver"] = config.DriverName
		check.Details["query"] = query
		check.Details["query_time"] = queryTime.String()

		if err != nil {
			check.Status = HealthStatusUnhealthy
			check.Error = err.Error()
			check.Message = fmt.Sprintf("Database query failed: %v", err)
		} else {
			check.Status = HealthStatusHealthy
			check.Message = fmt.Sprintf("Database check passed (query time: %v)", queryTime)
		}

		return check
	}
}

// NewHTTPCheck creates a new HTTP health check
func NewHTTPCheck(name string, config HTTPCheckConfig) *Check {
	return &Check{
		Name:       name,
		Type:       ServiceTypeHTTP,
		Enabled:    true,
		Critical:   false,
		Timeout:    config.Timeout,
		Interval:   30 * time.Second,
		MaxRetries: 3,
		Checker:    HTTPChecker(config),
		Config:     config,
	}
}

// NewDatabaseCheck creates a new database health check
func NewDatabaseCheck(name string, config DatabaseCheckConfig) *Check {
	return &Check{
		Name:       name,
		Type:       ServiceTypeDatabase,
		Enabled:    true,
		Critical:   true, // Database checks are typically critical
		Timeout:    config.Timeout,
		Interval:   30 * time.Second,
		MaxRetries: 3,
		Checker:    DatabaseChecker(config),
		Config:     config,
	}
}
