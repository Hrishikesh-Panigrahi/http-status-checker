package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPChecker handles HTTP status checking with advanced features
type HTTPChecker struct {
	client *http.Client
	config CheckerConfig
}

// CheckerConfig contains configuration for the HTTP checker
type CheckerConfig struct {
	UserAgent             string
	Timeout               time.Duration
	FollowRedirects       bool
	MaxRedirects          int
	VerifySSL             bool
	AllowInsecure         bool
	CustomHeaders         map[string]string
	MaxIdleConns          int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
}

// CheckResult represents the result of a single HTTP check
type CheckResult struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	StatusCode       int               `json:"status_code"`
	StatusText       string            `json:"status_text"`
	ResponseTime     time.Duration     `json:"response_time"`
	ResponseSize     int64             `json:"response_size"`
	ResponseHeaders  map[string]string `json:"response_headers"`
	IPAddress        string            `json:"ip_address"`
	TLSVersion       string            `json:"tls_version,omitempty"`
	TLSCipher        string            `json:"tls_cipher,omitempty"`
	CertificateInfo  *CertificateInfo  `json:"certificate_info,omitempty"`
	Error            string            `json:"error,omitempty"`
	Success          bool              `json:"success"`
	RedirectChain    []string          `json:"redirect_chain,omitempty"`
	DNSLookupTime    time.Duration     `json:"dns_lookup_time"`
	ConnectTime      time.Duration     `json:"connect_time"`
	TLSHandshakeTime time.Duration     `json:"tls_handshake_time"`
	FirstByteTime    time.Duration     `json:"first_byte_time"`
}

// CertificateInfo contains SSL/TLS certificate information
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	IsValid      bool      `json:"is_valid"`
	DaysUntilExp int       `json:"days_until_expiry"`
}

// DefaultCheckerConfig returns a checker configuration with sensible defaults
func DefaultCheckerConfig() CheckerConfig {
	return CheckerConfig{
		UserAgent:             "http-status-checker/2.0",
		Timeout:               10 * time.Second,
		FollowRedirects:       true,
		MaxRedirects:          10,
		VerifySSL:             true,
		AllowInsecure:         false,
		CustomHeaders:         make(map[string]string),
		MaxIdleConns:          100,
		MaxConnsPerHost:       10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
}

// NewHTTPChecker creates a new HTTP checker with the given configuration
func NewHTTPChecker(config CheckerConfig) *HTTPChecker {
	// Create custom transport
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          config.MaxIdleConns,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Configure TLS
	if config.AllowInsecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else if !config.VerifySSL {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	// Configure redirect handling
	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if config.MaxRedirects > 0 {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return nil
		}
	}

	return &HTTPChecker{
		client: client,
		config: config,
	}
}

// Check performs an HTTP check on the given URL
func (c *HTTPChecker) Check(ctx context.Context, targetURL string) (*CheckResult, error) {
	return c.CheckWithMethod(ctx, "GET", targetURL)
}

// CheckWithMethod performs an HTTP check with the specified method
func (c *HTTPChecker) CheckWithMethod(ctx context.Context, method, targetURL string) (*CheckResult, error) {
	// Validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Initialize result
	result := &CheckResult{
		URL:    targetURL,
		Method: method,
	}

	// Track timing
	startTime := time.Now()
	var dnsLookupTime, connectTime, tlsHandshakeTime, firstByteTime time.Duration

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result, nil
	}

	// Set headers
	req.Header.Set("User-Agent", c.config.UserAgent)
	for key, value := range c.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	// Track DNS lookup time
	dnsStart := time.Now()
	if ips, err := net.LookupIP(parsedURL.Hostname()); err == nil && len(ips) > 0 {
		result.IPAddress = ips[0].String()
	}
	dnsLookupTime = time.Since(dnsStart)

	// Perform request
	connectStart := time.Now()
	resp, err := c.client.Do(req)
	connectTime = time.Since(connectStart)
	result.ResponseTime = time.Since(startTime)

	if err != nil {
		result.Error = fmt.Sprintf("Request failed: %v", err)
		result.DNSLookupTime = dnsLookupTime
		result.ConnectTime = connectTime
		return result, nil
	}
	defer resp.Body.Close()

	// Record first byte time
	firstByteTime = time.Since(startTime)

	// Extract response information
	result.StatusCode = resp.StatusCode
	result.StatusText = resp.Status
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	result.ResponseSize = resp.ContentLength
	result.DNSLookupTime = dnsLookupTime
	result.ConnectTime = connectTime
	result.FirstByteTime = firstByteTime

	// Extract headers
	result.ResponseHeaders = make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			result.ResponseHeaders[key] = values[0]
		}
	}

	// Extract TLS information if HTTPS
	if resp.TLS != nil {
		tlsHandshakeTime = time.Since(connectStart)
		result.TLSHandshakeTime = tlsHandshakeTime

		// TLS version
		switch resp.TLS.Version {
		case tls.VersionTLS10:
			result.TLSVersion = "TLS 1.0"
		case tls.VersionTLS11:
			result.TLSVersion = "TLS 1.1"
		case tls.VersionTLS12:
			result.TLSVersion = "TLS 1.2"
		case tls.VersionTLS13:
			result.TLSVersion = "TLS 1.3"
		}

		// Cipher suite
		result.TLSCipher = tls.CipherSuiteName(resp.TLS.CipherSuite)

		// Certificate information
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			result.CertificateInfo = &CertificateInfo{
				Subject:      cert.Subject.String(),
				Issuer:       cert.Issuer.String(),
				SerialNumber: cert.SerialNumber.String(),
				NotBefore:    cert.NotBefore,
				NotAfter:     cert.NotAfter,
				IsValid:      time.Now().After(cert.NotBefore) && time.Now().Before(cert.NotAfter),
				DaysUntilExp: int(time.Until(cert.NotAfter).Hours() / 24),
			}
		}
	}

	// Track redirect chain
	if resp.Request.URL.String() != targetURL {
		result.RedirectChain = []string{resp.Request.URL.String()}
	}

	return result, nil
}

// CheckMultiple performs multiple checks on different URLs concurrently
func (c *HTTPChecker) CheckMultiple(ctx context.Context, urls []string) ([]*CheckResult, error) {
	results := make([]*CheckResult, len(urls))
	errChan := make(chan error, len(urls))
	resultChan := make(chan struct {
		index  int
		result *CheckResult
	}, len(urls))

	// Start checks concurrently
	for i, url := range urls {
		go func(index int, targetURL string) {
			result, err := c.Check(ctx, targetURL)
			if err != nil {
				errChan <- err
				return
			}
			resultChan <- struct {
				index  int
				result *CheckResult
			}{index, result}
		}(i, url)
	}

	// Collect results
	completed := 0
	for completed < len(urls) {
		select {
		case result := <-resultChan:
			results[result.index] = result.result
			completed++
		case err := <-errChan:
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return results, nil
}

// CheckHealth performs a basic health check
func (c *HTTPChecker) CheckHealth(ctx context.Context, url string, expectedStatus int) bool {
	result, err := c.Check(ctx, url)
	if err != nil {
		return false
	}

	if expectedStatus > 0 {
		return result.StatusCode == expectedStatus
	}

	return result.Success
}

// ValidateURL validates and normalizes a URL
func ValidateURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}

	// Add https:// if no scheme is provided
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %w", err)
	}

	if parsedURL.Host == "" {
		return "", fmt.Errorf("URL must have a valid host")
	}

	return rawURL, nil
}

// GetStatusCategory returns a human-readable category for the HTTP status code
func GetStatusCategory(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "Success"
	case statusCode >= 300 && statusCode < 400:
		return "Redirection"
	case statusCode >= 400 && statusCode < 500:
		return "Client Error"
	case statusCode >= 500 && statusCode < 600:
		return "Server Error"
	default:
		return "Unknown"
	}
}

// FormatResponseTime formats response time in a human-readable way
func FormatResponseTime(duration time.Duration) string {
	if duration < time.Millisecond {
		return fmt.Sprintf("%.2f μs", float64(duration.Nanoseconds())/1000.0)
	}
	if duration < time.Second {
		return fmt.Sprintf("%.2f ms", float64(duration.Nanoseconds())/1000000.0)
	}
	return fmt.Sprintf("%.2f s", duration.Seconds())
}
