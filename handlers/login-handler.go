package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/jaycynth/behaviour-analysis-totp-phishing/models"
	"github.com/jaycynth/behaviour-analysis-totp-phishing/services"
	"github.com/jaycynth/behaviour-analysis-totp-phishing/utils"
)

type LoginHandler struct {
	PhishingService *services.PhishingService
}

func NewLoginHandler(phishingService *services.PhishingService) *LoginHandler {
	return &LoginHandler{PhishingService: phishingService}
}

func (h *LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var attempt models.LoginAttempt

	// Decode JSON payload
	if err := json.NewDecoder(r.Body).Decode(&attempt); err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		log.Println("[ERROR] JSON decoding failed:", err)
		return
	}
	defer r.Body.Close()

	attempt.CreatedAt = time.Now()

	// Fetch GeoIP location asynchronously
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		if location, err := utils.GetCountry(attempt.IPAddress); err == nil {
			attempt.Location = location
		} else {
			log.Println("[WARNING] GeoIP lookup failed for IP:", attempt.IPAddress, err)
		}
	}()

	// Detect phishing behavior
	h.PhishingService.DetectPhishing(ctx, &attempt)

	// Ensure GeoIP lookup finishes before responding
	wg.Wait()

	response := map[string]interface{}{
		"message":     "Login attempt recorded",
		"is_phishing": attempt.IsPhishingRisk,
		"risk_factors": map[string]bool{
			"device_mismatch":   attempt.DeviceMismatch,
			"otp_replay":        attempt.OTPReplayDetected,
			"geo_distance_high": attempt.DistanceFromLast > 5000,
			"high_login_freq":   attempt.LoginFrequencyHigh,
			"multiple_ips":      attempt.MultipleIPsDetected,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		log.Println("[ERROR] Response encoding failed:", err)
	}
}
