package utils

import (
	"net"
	"net/http"
	"strings"
)

// GetClientIP extracts the real client IP address, considering proxy headers.
func GetClientIP(r *http.Request) string {
	// Prioritize X-Forwarded-For header (comma-separated list of proxies)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		for _, ip := range ips {
			trimmedIP := strings.TrimSpace(ip)
			if isValidIP(trimmedIP) {
				return trimmedIP
			}
		}
	}

	// Check X-Real-IP header (commonly set by Nginx)
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" && isValidIP(realIP) {
		return realIP
	}

	// Fallback to RemoteAddr (may include port, so we extract IP)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // Return as-is if parsing fails
	}

	return host
}

// isValidIP ensures the extracted value is a valid IPv4 or IPv6 address
func isValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}
