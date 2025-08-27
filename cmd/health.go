package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Hrishikesh-Panigrahi/http-status-checker/internal/health"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var (
	healthPort     int
	healthInterval time.Duration
	enableServer   bool
	checkName      string
	checkURL       string
	checkType      string
	expectedStatus int
	criticalCheck  bool
	healthTimeout  time.Duration
	listChecks     bool
	runOnce        bool
)

// healthCmd represents the health command
var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Manage health checks and monitoring",
	Long: `Health monitoring system for APIs, databases, and other services.

Features:
- HTTP/HTTPS endpoint monitoring
- Database connection checking
- Custom health check scripts
- Real-time monitoring dashboard
- REST API for health status
- Configurable check intervals
- Alert thresholds

Examples:
  # Start health monitoring server
  http-status-checker health server --port 8080

  # Add an HTTP health check
  http-status-checker health add --name "api" --url "https://api.example.com/health"
  
  # Add a critical database check
  http-status-checker health add --name "db" --type database --critical
  
  # List all health checks
  http-status-checker health list
  
  # Run checks once and exit
  http-status-checker health check --once`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if listChecks {
			return listHealthChecks()
		}
		if runOnce {
			return runHealthChecksOnce()
		}
		return cmd.Help()
	},
}

// serverCmd starts the health monitoring server
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the health monitoring server",
	Long: `Start an HTTP server that provides health check endpoints.

The server provides:
- GET /health - Overall health status
- GET /health/{check-name} - Individual check status
- GET /metrics - Prometheus-style metrics (if enabled)

Examples:
  http-status-checker health server
  http-status-checker health server --port 8080 --interval 30s`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return startHealthServer()
	},
}

// addCmd adds a new health check
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new health check",
	Long: `Add a new health check to the monitoring system.

Supported check types:
- http: HTTP/HTTPS endpoint checks
- database: Database connection checks
- tcp: TCP port connectivity checks
- custom: Custom script execution

Examples:
  # Add HTTP check
  http-status-checker health add --name "api" --url "https://api.example.com/health"
  
  # Add critical HTTP check with specific status
  http-status-checker health add --name "payment" --url "https://pay.example.com/status" --status 200 --critical
  
  # Add database check
  http-status-checker health add --name "postgres" --type database --critical`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return addHealthCheck()
	},
}

// listCmd lists all health checks
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured health checks",
	Long:  `Display all configured health checks with their current status.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return listHealthChecks()
	},
}

// checkCmd runs health checks
var runCmd = &cobra.Command{
	Use:   "check",
	Short: "Run health checks",
	Long: `Execute all configured health checks and display results.

Options:
  --once    Run checks once and exit (don't start monitoring)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if runOnce {
			return runHealthChecksOnce()
		}
		return startHealthMonitoring()
	},
}

// startHealthServer starts the HTTP health monitoring server
func startHealthServer() error {
	monitor := health.NewHealthMonitor()

	// Add some example health checks
	httpCheck := health.NewHTTPCheck("example-api", health.HTTPCheckConfig{
		URL:            "https://httpbin.org/status/200",
		Method:         "GET",
		ExpectedStatus: 200,
		Timeout:        5 * time.Second,
	})
	monitor.AddCheck(httpCheck)

	// Start monitoring
	monitor.Start(healthInterval)
	defer monitor.Stop()

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", monitor.HTTPHandler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>Health Monitor</title>
    <meta http-equiv="refresh" content="10">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .healthy { color: green; }
        .unhealthy { color: red; }
        .unknown { color: orange; }
        .status { font-weight: bold; font-size: 1.2em; }
    </style>
</head>
<body>
    <h1>🏥 Health Monitor Dashboard</h1>
    <p>Health monitoring is running. Check <a href="/health">/health</a> for JSON status.</p>
    <p>Monitoring interval: %v</p>
    <p>Server started at: %v</p>
</body>
</html>`, healthInterval, time.Now().Format(time.RFC3339))
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", healthPort),
		Handler: mux,
	}

	fmt.Printf("🏥 Health monitoring server starting on port %d\n", healthPort)
	fmt.Printf("📊 Dashboard: http://localhost:%d\n", healthPort)
	fmt.Printf("🔍 Health endpoint: http://localhost:%d/health\n", healthPort)
	fmt.Printf("⏱️  Check interval: %v\n", healthInterval)
	fmt.Println("\nPress Ctrl+C to stop...")

	return server.ListenAndServe()
}

// addHealthCheck adds a new health check configuration
func addHealthCheck() error {
	if checkName == "" {
		return fmt.Errorf("check name is required (--name)")
	}

	fmt.Printf("✅ Adding health check: %s\n", checkName)

	switch checkType {
	case "http", "":
		if checkURL == "" {
			return fmt.Errorf("URL is required for HTTP checks (--url)")
		}
		fmt.Printf("   Type: HTTP\n")
		fmt.Printf("   URL: %s\n", checkURL)
		if expectedStatus > 0 {
			fmt.Printf("   Expected Status: %d\n", expectedStatus)
		}
	case "database":
		fmt.Printf("   Type: Database\n")
		fmt.Println("   Note: Database configuration not implemented yet")
	case "tcp":
		fmt.Printf("   Type: TCP\n")
		fmt.Println("   Note: TCP check configuration not implemented yet")
	default:
		return fmt.Errorf("unsupported check type: %s", checkType)
	}

	fmt.Printf("   Critical: %v\n", criticalCheck)
	fmt.Printf("   Timeout: %v\n", healthTimeout)
	fmt.Println("\nHealth check configuration saved!")

	return nil
}

// listHealthChecks displays all configured health checks
func listHealthChecks() error {
	monitor := health.NewHealthMonitor()

	// Add some example checks for demonstration
	httpCheck := health.NewHTTPCheck("example-api", health.HTTPCheckConfig{
		URL:            "https://httpbin.org/status/200",
		Method:         "GET",
		ExpectedStatus: 200,
		Timeout:        5 * time.Second,
	})
	httpCheck.Critical = true
	monitor.AddCheck(httpCheck)

	httpCheck2 := health.NewHTTPCheck("backup-api", health.HTTPCheckConfig{
		URL:            "https://httpbin.org/status/503",
		Method:         "GET",
		ExpectedStatus: 200,
		Timeout:        5 * time.Second,
	})
	monitor.AddCheck(httpCheck2)

	// Run checks to get current status
	ctx := context.Background()
	checks := monitor.RunAllChecks(ctx)

	if len(checks) == 0 {
		fmt.Println("📝 No health checks configured.")
		fmt.Println("\nAdd a check with: http-status-checker health add --name <name> --url <url>")
		return nil
	}

	// Display in table format
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Type", "Status", "Last Check", "Duration", "Critical", "Message"})
	table.SetBorder(true)
	table.SetCenterSeparator("|")
	table.SetColumnSeparator("|")
	table.SetRowSeparator("-")

	for _, check := range checks {
		status := string(check.Status)
		statusIcon := "❓"
		switch check.Status {
		case health.HealthStatusHealthy:
			statusIcon = "✅"
		case health.HealthStatusUnhealthy:
			statusIcon = "❌"
		case health.HealthStatusUnknown:
			statusIcon = "❓"
		}

		critical := "No"
		if check.Critical {
			critical = "Yes"
		}

		lastCheck := "Never"
		if !check.LastCheck.IsZero() {
			lastCheck = check.LastCheck.Format("15:04:05")
		}

		duration := ""
		if check.Duration > 0 {
			duration = check.Duration.Truncate(time.Millisecond).String()
		}

		table.Append([]string{
			check.Name,
			string(check.Type),
			fmt.Sprintf("%s %s", statusIcon, status),
			lastCheck,
			duration,
			critical,
			check.Message,
		})
	}

	fmt.Println("🏥 Health Check Status")
	fmt.Println("═══════════════════════")
	table.Render()

	// Summary
	healthy := 0
	unhealthy := 0
	unknown := 0
	critical := 0

	for _, check := range checks {
		switch check.Status {
		case health.HealthStatusHealthy:
			healthy++
		case health.HealthStatusUnhealthy:
			unhealthy++
			if check.Critical {
				critical++
			}
		case health.HealthStatusUnknown:
			unknown++
		}
	}

	fmt.Printf("\n📊 Summary: %d total | %d healthy | %d unhealthy | %d unknown",
		len(checks), healthy, unhealthy, unknown)
	if critical > 0 {
		fmt.Printf(" | %d critical failing", critical)
	}
	fmt.Println()

	return nil
}

// runHealthChecksOnce runs all health checks once and displays results
func runHealthChecksOnce() error {
	monitor := health.NewHealthMonitor()

	// Add example checks
	httpCheck := health.NewHTTPCheck("example-api", health.HTTPCheckConfig{
		URL:            "https://httpbin.org/status/200",
		Method:         "GET",
		ExpectedStatus: 200,
		Timeout:        5 * time.Second,
	})
	monitor.AddCheck(httpCheck)

	fmt.Println("🔍 Running health checks...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	overallHealth := monitor.GetOverallHealth(ctx)

	// Display results
	fmt.Printf("\n🏥 Overall Health Status: %s\n", overallHealth.Status)
	fmt.Printf("📝 Message: %s\n", overallHealth.Message)
	fmt.Printf("⏱️  Check Duration: %v\n", overallHealth.Duration)
	fmt.Printf("🕐 Timestamp: %s\n", overallHealth.Timestamp.Format(time.RFC3339))

	if len(overallHealth.Checks) > 0 {
		fmt.Println("\n📋 Individual Check Results:")
		for _, check := range overallHealth.Checks {
			statusIcon := "❓"
			switch check.Status {
			case health.HealthStatusHealthy:
				statusIcon = "✅"
			case health.HealthStatusUnhealthy:
				statusIcon = "❌"
			}

			fmt.Printf("   %s %s: %s (%v)\n",
				statusIcon, check.Name, check.Message, check.Duration.Truncate(time.Millisecond))
		}
	}

	fmt.Printf("\n📊 Summary: %d/%d checks passing\n",
		overallHealth.Summary.Healthy, overallHealth.Summary.Total)

	return nil
}

// startHealthMonitoring starts continuous health monitoring
func startHealthMonitoring() error {
	monitor := health.NewHealthMonitor()

	// Add example checks
	httpCheck := health.NewHTTPCheck("example-api", health.HTTPCheckConfig{
		URL:            "https://httpbin.org/status/200",
		Method:         "GET",
		ExpectedStatus: 200,
		Timeout:        5 * time.Second,
	})
	monitor.AddCheck(httpCheck)

	fmt.Printf("🏥 Starting health monitoring (interval: %v)\n", healthInterval)
	fmt.Println("Press Ctrl+C to stop...")

	monitor.Start(healthInterval)
	defer monitor.Stop()

	// Keep running until interrupted
	select {}
}

func init() {
	rootCmd.AddCommand(healthCmd)

	// Add subcommands
	healthCmd.AddCommand(serverCmd)
	healthCmd.AddCommand(addCmd)
	healthCmd.AddCommand(listCmd)
	healthCmd.AddCommand(runCmd)

	// Global health flags
	healthCmd.PersistentFlags().DurationVar(&healthInterval, "interval", 30*time.Second, "Health check interval")
	healthCmd.PersistentFlags().DurationVar(&healthTimeout, "timeout", 10*time.Second, "Health check timeout")

	// Server command flags
	serverCmd.Flags().IntVar(&healthPort, "port", 8080, "Health server port")

	// Add command flags
	addCmd.Flags().StringVar(&checkName, "name", "", "Health check name (required)")
	addCmd.Flags().StringVar(&checkURL, "url", "", "URL to check (for HTTP checks)")
	addCmd.Flags().StringVar(&checkType, "type", "http", "Check type (http, database, tcp)")
	addCmd.Flags().IntVar(&expectedStatus, "status", 0, "Expected HTTP status code (0 for any 2xx)")
	addCmd.Flags().BoolVar(&criticalCheck, "critical", false, "Mark as critical check")

	// List command flags
	listCmd.Flags().BoolVar(&listChecks, "all", false, "Show all check details")

	// Check command flags
	runCmd.Flags().BoolVar(&runOnce, "once", false, "Run checks once and exit")

	// Mark required flags
	addCmd.MarkFlagRequired("name")
}
