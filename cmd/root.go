package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "http-status-checker",
	Short: "A powerful CLI tool for website monitoring and health checks",
	Long: `HTTP Status Checker 2.0 - A comprehensive CLI tool for website monitoring, 
health checks, and network diagnostics.

Features:
- Advanced HTTP status checking with detailed metrics
- Real-time health monitoring with dashboard
- Cross-platform network diagnostics
- SSL/TLS certificate analysis
- Structured logging and configuration management

Examples:
  http-status-checker check google.com
  http-status-checker health server --port 8080
  http-status-checker ip --dns
  
For backward compatibility, you can also use:
  http-status-checker [url] [pings]`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
}
