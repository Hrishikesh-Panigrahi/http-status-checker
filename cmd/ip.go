package cmd

import (
	"fmt"
	"os"

	"github.com/Hrishikesh-Panigrahi/http-status-checker/internal/network"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var (
	showDNS    bool
	showTable  bool
	showAll    bool
	jsonFormat bool
)

// ipCmd represents the ip command
var ipCmd = &cobra.Command{
	Use:   "ip [hostname]",
	Short: "Get IP address information (local or remote)",
	Long: `Get comprehensive IP address information including local machine IP,
remote hostname resolution, and DNS server information.

Features:
- Cross-platform local IP detection
- IPv4 and IPv6 support
- DNS server information
- Network interface details
- Table or JSON output

Examples:
  http-status-checker ip                    # Show local IP
  http-status-checker ip google.com         # Show remote IP
  http-status-checker ip --dns              # Show DNS servers
  http-status-checker ip google.com --all   # Show everything
  http-status-checker ip --json             # JSON output`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var hostname string
		if len(args) == 1 {
			hostname = args[0]
		}

		// Get network information
		netInfo, err := network.GetNetworkInfo(hostname)
		if err != nil {
			return fmt.Errorf("failed to get network information: %w", err)
		}

		// Display results based on flags
		if jsonFormat {
			return displayNetworkInfoJSON(netInfo)
		} else if showTable {
			return displayNetworkInfoTable(netInfo)
		} else {
			return displayNetworkInfoText(netInfo, hostname == "")
		}
	},
}

// displayNetworkInfoText displays network info in text format
func displayNetworkInfoText(info *network.NetworkInfo, localOnly bool) error {
	fmt.Println()

	if localOnly {
		fmt.Println("🖥️  Local Machine Network Information")
		fmt.Println("═══════════════════════════════════════")

		if info.LocalIP.IPv4 != "" {
			fmt.Printf("   IPv4 Address: %s\n", info.LocalIP.IPv4)
		}
		if info.LocalIP.IPv6 != "" {
			fmt.Printf("   IPv6 Address: %s\n", info.LocalIP.IPv6)
		}
	} else {
		fmt.Printf("🌐 Network Information for %s\n", info.Hostname)
		fmt.Println("═══════════════════════════════════════")

		fmt.Println("\n📍 Local Machine:")
		if info.LocalIP.IPv4 != "" {
			fmt.Printf("   IPv4 Address: %s\n", info.LocalIP.IPv4)
		}
		if info.LocalIP.IPv6 != "" {
			fmt.Printf("   IPv6 Address: %s\n", info.LocalIP.IPv6)
		}

		fmt.Printf("\n🎯 Remote Host (%s):\n", info.Hostname)
		if info.RemoteIP.IPv4 != "" {
			fmt.Printf("   IPv4 Address: %s\n", info.RemoteIP.IPv4)
		}
		if info.RemoteIP.IPv6 != "" {
			fmt.Printf("   IPv6 Address: %s\n", info.RemoteIP.IPv6)
		}
	}

	// Show DNS information if requested or if showing all
	if showDNS || showAll {
		fmt.Println("\n🌍 DNS Servers:")
		if len(info.DNS.Servers) > 0 {
			for i, server := range info.DNS.Servers {
				if i == 0 && info.DNS.Primary != "" {
					fmt.Printf("   Primary:   %s\n", server)
				} else {
					fmt.Printf("   Secondary: %s\n", server)
				}
			}
		} else {
			fmt.Println("   No DNS servers found")
		}
	}

	fmt.Println()
	return nil
}

// displayNetworkInfoTable displays network info in table format
func displayNetworkInfoTable(info *network.NetworkInfo) error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Type", "Address Type", "Address"})
	table.SetBorder(true)
	table.SetCenterSeparator("|")
	table.SetColumnSeparator("|")
	table.SetRowSeparator("-")

	// Local IP information
	if info.LocalIP.IPv4 != "" {
		table.Append([]string{"Local", "IPv4", info.LocalIP.IPv4})
	}
	if info.LocalIP.IPv6 != "" {
		table.Append([]string{"Local", "IPv6", info.LocalIP.IPv6})
	}

	// Remote IP information
	if info.Hostname != "" {
		if info.RemoteIP.IPv4 != "" {
			table.Append([]string{fmt.Sprintf("Remote (%s)", info.Hostname), "IPv4", info.RemoteIP.IPv4})
		}
		if info.RemoteIP.IPv6 != "" {
			table.Append([]string{fmt.Sprintf("Remote (%s)", info.Hostname), "IPv6", info.RemoteIP.IPv6})
		}
	}

	// DNS servers
	if showDNS || showAll {
		for i, server := range info.DNS.Servers {
			dnsType := "DNS Secondary"
			if i == 0 {
				dnsType = "DNS Primary"
			}
			table.Append([]string{dnsType, "IPv4/IPv6", server})
		}
	}

	table.Render()
	return nil
}

// displayNetworkInfoJSON displays network info in JSON format
func displayNetworkInfoJSON(info *network.NetworkInfo) error {
	// This would implement JSON marshaling and output
	fmt.Printf("JSON output not implemented yet for: %+v\n", info)
	return nil
}

func init() {
	rootCmd.AddCommand(ipCmd)

	// Add flags for enhanced functionality
	ipCmd.Flags().BoolVar(&showDNS, "dns", false, "Show DNS server information")
	ipCmd.Flags().BoolVar(&showTable, "table", false, "Display results in table format")
	ipCmd.Flags().BoolVar(&showAll, "all", false, "Show all available information")
	ipCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output in JSON format")

	// Mark table and json as mutually exclusive
	ipCmd.MarkFlagsMutuallyExclusive("table", "json")

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// ipCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// ipCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
