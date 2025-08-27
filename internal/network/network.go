package network

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// IPInfo represents IP address information
type IPInfo struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

// DNSInfo represents DNS server information
type DNSInfo struct {
	Servers []string `json:"servers"`
	Primary string   `json:"primary"`
}

// NetworkInfo contains comprehensive network information
type NetworkInfo struct {
	LocalIP   IPInfo  `json:"local_ip"`
	RemoteIP  IPInfo  `json:"remote_ip"`
	DNS       DNSInfo `json:"dns"`
	Hostname  string  `json:"hostname"`
	Interface string  `json:"interface"`
}

// GetLocalIPAddress returns the local machine's IP address(es)
func GetLocalIPAddress() (*IPInfo, error) {
	ipInfo := &IPInfo{}

	// Try to get IP by connecting to a remote address (doesn't actually send data)
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		ipInfo.IPv4 = localAddr.IP.String()
	}

	// Also try to get all interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Skip down or loopback interfaces
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			if ip.To4() != nil && ipInfo.IPv4 == "" {
				ipInfo.IPv4 = ip.String()
			} else if ip.To4() == nil && ipInfo.IPv6 == "" {
				ipInfo.IPv6 = ip.String()
			}
		}
	}

	return ipInfo, nil
}

// GetRemoteIPAddress resolves the IP address(es) of a hostname
func GetRemoteIPAddress(hostname string) (*IPInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname: %w", err)
	}

	ipInfo := &IPInfo{}
	for _, ip := range ips {
		if ip.IP.To4() != nil && ipInfo.IPv4 == "" {
			ipInfo.IPv4 = ip.IP.String()
		} else if ip.IP.To4() == nil && ipInfo.IPv6 == "" {
			ipInfo.IPv6 = ip.IP.String()
		}
	}

	return ipInfo, nil
}

// GetDNSServers returns the DNS servers configured on the system
func GetDNSServers() (*DNSInfo, error) {
	dnsInfo := &DNSInfo{
		Servers: make([]string, 0),
	}

	switch runtime.GOOS {
	case "windows":
		return getDNSServersWindows()
	case "linux", "darwin":
		return getDNSServersUnix()
	default:
		return dnsInfo, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// getDNSServersWindows gets DNS servers on Windows using ipconfig
func getDNSServersWindows() (*DNSInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ipconfig", "/all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run ipconfig: %w", err)
	}

	dnsInfo := &DNSInfo{
		Servers: make([]string, 0),
	}

	// Parse ipconfig output for DNS servers
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "dns servers") {
			// Look for IP addresses in this line and the next few lines
			for j := i; j < len(lines) && j < i+5; j++ {
				matches := ipRegex.FindAllString(lines[j], -1)
				for _, match := range matches {
					if !contains(dnsInfo.Servers, match) && !isPrivateOrLoopback(match) {
						dnsInfo.Servers = append(dnsInfo.Servers, match)
					}
				}
			}
			break
		}
	}

	if len(dnsInfo.Servers) > 0 {
		dnsInfo.Primary = dnsInfo.Servers[0]
	}

	return dnsInfo, nil
}

// getDNSServersUnix gets DNS servers on Unix-like systems from /etc/resolv.conf
func getDNSServersUnix() (*DNSInfo, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to open /etc/resolv.conf: %w", err)
	}
	defer file.Close()

	dnsInfo := &DNSInfo{
		Servers: make([]string, 0),
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := fields[1]
				if net.ParseIP(ip) != nil && !contains(dnsInfo.Servers, ip) {
					dnsInfo.Servers = append(dnsInfo.Servers, ip)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read /etc/resolv.conf: %w", err)
	}

	if len(dnsInfo.Servers) > 0 {
		dnsInfo.Primary = dnsInfo.Servers[0]
	}

	return dnsInfo, nil
}

// GetNetworkInfo returns comprehensive network information
func GetNetworkInfo(hostname string) (*NetworkInfo, error) {
	info := &NetworkInfo{}

	// Get local IP
	localIP, err := GetLocalIPAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to get local IP: %w", err)
	}
	info.LocalIP = *localIP

	// Get remote IP if hostname provided
	if hostname != "" {
		remoteIP, err := GetRemoteIPAddress(hostname)
		if err != nil {
			return nil, fmt.Errorf("failed to get remote IP: %w", err)
		}
		info.RemoteIP = *remoteIP
		info.Hostname = hostname
	}

	// Get DNS servers
	dns, err := GetDNSServers()
	if err != nil {
		// Don't fail if we can't get DNS info, just log it
		dns = &DNSInfo{Servers: []string{}}
	}
	info.DNS = *dns

	return info, nil
}

// TestNetworkConnectivity tests basic network connectivity
func TestNetworkConnectivity(host string, port int, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", host, port, err)
	}
	defer conn.Close()
	return nil
}

// TracerouteStep represents a single hop in a traceroute
type TracerouteStep struct {
	Hop      int           `json:"hop"`
	IP       string        `json:"ip"`
	Hostname string        `json:"hostname,omitempty"`
	RTT      time.Duration `json:"rtt"`
	Timeout  bool          `json:"timeout"`
}

// SimpleTraceroute performs a basic traceroute (simplified implementation)
func SimpleTraceroute(hostname string, maxHops int) ([]TracerouteStep, error) {
	steps := make([]TracerouteStep, 0, maxHops)

	// This is a simplified implementation
	// For production use, you might want to use a proper traceroute implementation
	// or shell out to the system traceroute command

	target, err := net.ResolveIPAddr("ip", hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname: %w", err)
	}

	// Just return the final destination for now
	// A full implementation would use raw sockets and ICMP
	step := TracerouteStep{
		Hop:      1,
		IP:       target.IP.String(),
		Hostname: hostname,
		RTT:      0, // Would be measured in real implementation
		Timeout:  false,
	}

	steps = append(steps, step)
	return steps, nil
}

// Utility functions

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// isPrivateOrLoopback checks if an IP is private or loopback
func isPrivateOrLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// ValidateHostname validates if a hostname is properly formatted
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}

	// Basic hostname validation
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("invalid hostname format")
	}

	return nil
}
