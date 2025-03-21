package utils

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// CheckIPReputation checks if an IP is flagged as malicious using an external API
func CheckIPReputation(ip string) string {
	apiURL := "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("Error creating request for IP reputation check: %v", err)
		return "unknown"
	}

	req.Header.Set("Key", "YOUR_ABUSEIPDB_API_KEY")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error checking IP reputation: %v", err)
		return "unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return "malicious"
	}
	return "clean"
}

// IsVPN checks if an IP belongs to a known VPN provider
func IsVPN(ip string) bool {
	vpnList := []string{
		"expressvpn.com",
		"nordvpn.com",
		"cyberghostvpn.com",
		"surfshark.com",
		"privateinternetaccess.com",
		"vyprvpn.com",
	}

	for _, vpnProvider := range vpnList {
		if strings.Contains(ip, vpnProvider) {
			return true
		}
	}
	return false
}

// IsTorExitNode checks if an IP is a known Tor exit node
func IsTorExitNode(ip string) bool {
	apiURL := "https://check.torproject.org/torbulkexitlist"
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(apiURL)
	if err != nil {
		log.Printf("Error fetching Tor exit nodes: %v", err)
		return false
	}
	defer resp.Body.Close()

	var torExitNodes []byte
	if _, err := resp.Body.Read(torExitNodes); err != nil {
		log.Printf("Error reading Tor exit node list: %v", err)
		return false
	}

	return strings.Contains(string(torExitNodes), ip)
}
