package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Hrishikesh-Panigrahi/http-status-checker/internal/checker"
	"github.com/Hrishikesh-Panigrahi/http-status-checker/internal/config"
	"github.com/Hrishikesh-Panigrahi/http-status-checker/pkg/logger"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

// StatusCheckResult contains the overall results of status checking
type StatusCheckResult struct {
	URL         string                 `json:"url"`
	TotalPings  int                    `json:"total_pings"`
	Checks      []*checker.CheckResult `json:"checks"`
	AvgPing     float64                `json:"avg_ping_ms"`
	SuccessRate float64                `json:"success_rate"`
}

var (
	cfg            *config.Config
	log            *logger.Logger
	outputFormat   string
	verbose        bool
	jsonOutput     bool
	followRedirect bool
	timeout        time.Duration
)

// initializeCheckCommand initializes configuration and logging for the check command
func initializeCheckCommand() error {
	var err error

	// Load configuration
	configPath := config.GetDefaultConfigPath()
	cfg, err = config.LoadConfig(configPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Initialize logger
	logConfig := logger.LoggerConfig{
		Level:      cfg.Logging.Level,
		Format:     cfg.Logging.Format,
		Output:     cfg.Logging.Output,
		File:       cfg.Logging.File,
		MaxSize:    cfg.Logging.MaxSize,
		MaxBackups: cfg.Logging.MaxBackups,
		MaxAge:     cfg.Logging.MaxAge,
	}

	log, err = logger.NewLogger(logConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	return nil
}

// performStatusChecks performs multiple status checks using the new checker package
func performStatusChecks(targetURL string, pings int) (*StatusCheckResult, error) {
	if pings <= 0 || pings > cfg.Defaults.MaxPings {
		return nil, fmt.Errorf("ping count must be between 1 and %d", cfg.Defaults.MaxPings)
	}

	// Create checker configuration
	checkerConfig := checker.CheckerConfig{
		UserAgent:             cfg.HTTP.UserAgent,
		Timeout:               timeout,
		FollowRedirects:       followRedirect,
		MaxRedirects:          10,
		VerifySSL:             true,
		AllowInsecure:         false,
		CustomHeaders:         make(map[string]string),
		MaxIdleConns:          cfg.HTTP.MaxIdleConns,
		MaxConnsPerHost:       cfg.HTTP.MaxConnsPerHost,
		IdleConnTimeout:       cfg.HTTP.KeepAlive,
		TLSHandshakeTimeout:   cfg.HTTP.TLSHandshakeTimeout,
		ResponseHeaderTimeout: cfg.HTTP.ResponseHeaderTimeout,
	}

	httpChecker := checker.NewHTTPChecker(checkerConfig)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(pings)*timeout)
	defer cancel()

	result := &StatusCheckResult{
		URL:        targetURL,
		TotalPings: pings,
		Checks:     make([]*checker.CheckResult, 0, pings),
	}

	var totalPing int64
	var successCount int

	log.Info("Starting status checks",
		"url", targetURL,
		"pings", pings,
		"timeout", timeout)

	for i := 0; i < pings; i++ {
		checkResult, err := httpChecker.Check(ctx, targetURL)
		if err != nil {
			log.WithError(err).Error("Check failed", "attempt", i+1)
			checkResult = &checker.CheckResult{
				URL:          targetURL,
				Error:        err.Error(),
				Success:      false,
				ResponseTime: 0,
			}
		}

		result.Checks = append(result.Checks, checkResult)
		totalPing += int64(checkResult.ResponseTime.Milliseconds())

		if checkResult.Success {
			successCount++
		}

		log.LogCheckResult(targetURL, checkResult.StatusCode, checkResult.ResponseTime, checkResult.Success)

		// Add delay between requests (except for the last one)
		if i < pings-1 {
			time.Sleep(cfg.Defaults.DelayBetween)
		}
	}

	result.AvgPing = float64(totalPing) / float64(pings)
	result.SuccessRate = float64(successCount) / float64(pings) * 100

	log.Info("Status checks completed",
		"url", targetURL,
		"success_rate", result.SuccessRate,
		"avg_ping", result.AvgPing)

	return result, nil
}

// renderStatusTable renders the status check results in a table
func renderStatusTable(result *StatusCheckResult) {
	if jsonOutput {
		renderJSON(result)
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	headers := []string{"Check #", "Response Time", "IP Address", "Status Code", "TLS", "Status"}

	if verbose {
		headers = append(headers, "Details")
	}

	table.SetHeader(headers)
	table.SetBorder(true)
	table.SetCenterSeparator("|")
	table.SetColumnSeparator("|")
	table.SetRowSeparator("-")

	// Add color coding for better readability - match number of headers
	headerColors := make([]tablewriter.Colors, len(headers))
	for i := range headerColors {
		headerColors[i] = tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor}
	}
	table.SetHeaderColor(headerColors...)

	for i, check := range result.Checks {
		status := "❌"
		if check.Success {
			status = "✅"
		} else if check.StatusCode >= 300 && check.StatusCode < 400 {
			status = "🔀" // Redirect
		}

		responseTime := checker.FormatResponseTime(check.ResponseTime)
		statusCode := ""
		if check.StatusCode > 0 {
			statusCode = strconv.Itoa(check.StatusCode)
		}

		tlsInfo := "N/A"
		if check.TLSVersion != "" {
			tlsInfo = check.TLSVersion
		}

		row := []string{
			strconv.Itoa(i + 1),
			responseTime,
			check.IPAddress,
			statusCode,
			tlsInfo,
			status,
		}

		if verbose {
			details := ""
			if check.Error != "" {
				details = fmt.Sprintf("Error: %s", check.Error)
			} else if check.CertificateInfo != nil {
				details = fmt.Sprintf("Cert expires: %d days", check.CertificateInfo.DaysUntilExp)
			}
			row = append(row, details)
		}

		// Color coding based on status - match number of columns
		colors := make([]tablewriter.Colors, len(row))
		for i := range colors {
			colors[i] = tablewriter.Colors{}
		}

		// Color first and last columns based on status
		if check.Success {
			colors[0] = tablewriter.Colors{tablewriter.FgGreenColor}
			colors[len(colors)-1] = tablewriter.Colors{tablewriter.FgGreenColor}
		} else {
			colors[0] = tablewriter.Colors{tablewriter.FgRedColor}
			colors[len(colors)-1] = tablewriter.Colors{tablewriter.FgRedColor}
		}

		table.Rich(row, colors)
	}

	table.Render()

	// Print enhanced summary
	fmt.Printf("\n📊 Summary for %s:\n", result.URL)
	fmt.Printf("   • Total Checks: %d\n", result.TotalPings)
	fmt.Printf("   • Success Rate: %.1f%% (%d/%d)\n",
		result.SuccessRate,
		int(result.SuccessRate*float64(result.TotalPings)/100),
		result.TotalPings)
	fmt.Printf("   • Average Response Time: %.2f ms\n", result.AvgPing)

	// Calculate min/max response times
	if len(result.Checks) > 0 {
		minTime := result.Checks[0].ResponseTime
		maxTime := result.Checks[0].ResponseTime
		for _, check := range result.Checks {
			if check.ResponseTime < minTime {
				minTime = check.ResponseTime
			}
			if check.ResponseTime > maxTime {
				maxTime = check.ResponseTime
			}
		}
		fmt.Printf("   • Response Time Range: %s - %s\n",
			checker.FormatResponseTime(minTime),
			checker.FormatResponseTime(maxTime))
	}

	// Show certificate info if available
	if len(result.Checks) > 0 && result.Checks[0].CertificateInfo != nil {
		cert := result.Checks[0].CertificateInfo
		fmt.Printf("   • SSL Certificate: %s (expires in %d days)\n",
			cert.Subject, cert.DaysUntilExp)
	}

	fmt.Println()
}

// renderJSON outputs the result in JSON format
func renderJSON(result *StatusCheckResult) {
	// This would implement JSON output
	fmt.Printf("JSON output for %s (not implemented yet)\n", result.URL)
}

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check <url> [pings]",
	Short: "Check the status of a website with advanced monitoring",
	Long: `Check the status of a website and measure response times with detailed analysis.

Features:
- Response time measurement
- SSL/TLS certificate information
- Redirect chain tracking
- DNS lookup timing
- Configurable timeouts and headers
- JSON output support
	
Examples:
  http-status-checker check google.com
  http-status-checker check https://api.github.com 10
  http-status-checker check example.com 5 --verbose
  http-status-checker check api.example.com --json --timeout 30s`,
	Args: cobra.RangeArgs(1, 2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return initializeCheckCommand()
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate and normalize URL
		targetURL, err := checker.ValidateURL(args[0])
		if err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}

		// Parse ping count
		pings := cfg.Defaults.Pings
		if len(args) == 2 {
			if p, err := strconv.Atoi(args[1]); err != nil {
				return fmt.Errorf("invalid ping count '%s': must be a number", args[1])
			} else {
				pings = p
			}
		}

		// Validate ping count
		if pings <= 0 || pings > cfg.Defaults.MaxPings {
			return fmt.Errorf("ping count must be between 1 and %d", cfg.Defaults.MaxPings)
		}

		// Display start message
		if !jsonOutput {
			fmt.Printf("🌐 Checking URL: %s\n", targetURL)
			fmt.Printf("📡 Performing %d status checks with %s timeout...\n\n", pings, timeout)
		}

		// Perform status checks
		result, err := performStatusChecks(targetURL, pings)
		if err != nil {
			return fmt.Errorf("status check failed: %w", err)
		}

		// Render results
		renderStatusTable(result)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)

	// Add flags
	checkCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (table, json)")
	checkCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	checkCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output results in JSON format")
	checkCmd.Flags().BoolVar(&followRedirect, "follow-redirects", true, "Follow HTTP redirects")
	checkCmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "Request timeout")

	// Mark json and output as mutually exclusive
	checkCmd.MarkFlagsMutuallyExclusive("json", "output")
}
