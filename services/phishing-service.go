package services

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/jaycynth/behaviour-analysis-totp-phishing/models"
	"github.com/jaycynth/behaviour-analysis-totp-phishing/repository"
	"github.com/jaycynth/behaviour-analysis-totp-phishing/utils"
)

type PhishingService struct {
	Repo *repository.LoginAttemptRepository
}

func NewPhishingService(repo *repository.LoginAttemptRepository) *PhishingService {
	return &PhishingService{Repo: repo}
}

func (s *PhishingService) DetectPhishing(ctx context.Context, attempt *models.LoginAttempt) {
	tx := s.Repo.DB.Begin()

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			log.Printf("Panic recovered in DetectPhishing for user %s: %v", attempt.UserID, r)
		}
	}()

	// Fetch login history
	history, err := s.Repo.GetLastLogin(ctx, attempt.UserID, 50)
	if err != nil {
		log.Printf("Error fetching login history for user %s: %v", attempt.UserID, err)
		tx.Rollback()
		return
	}

	var lastLogin *models.LoginAttempt
	if len(history) > 0 {
		lastLogin = history[0] // Most recent login
	}

	// Compute behavioral baselines
	behavioralStats, commonPatterns := CalculateBehavioralBaselines(history)

	// Compute risk score based on various heuristics
	riskScore, alertMessages := ComputeRiskScore(attempt, lastLogin, behavioralStats, commonPatterns)

	// Parallel network-based heuristics
	riskScore += s.PerformNetworkAnalysis(ctx, attempt, &alertMessages)

	// Trigger Alerts if Necessary
	if riskScore > 75 {
		attempt.IsPhishingRisk = true
		SendSecurityAlerts(attempt, riskScore, alertMessages)
	}

	// Save Login Attempt Safely
	if err := tx.Create(attempt).Error; err != nil {
		log.Printf("Error saving login attempt for user %s: %v", attempt.UserID, err)
		tx.Rollback()
		return
	}

	if err := tx.Commit().Error; err != nil {
		log.Printf("Transaction commit error for user %s: %v", attempt.UserID, err)
		tx.Rollback()
	}
}

func CalculateBehavioralBaselines(logins []*models.LoginAttempt) (map[string]float64, map[string]string) {
	behavioralStats := make(map[string]float64)
	commonPatterns := make(map[string]string)

	if len(logins) == 0 {
		// Return default values if there's no login history
		behavioralStats["average_login_interval"] = 0
		behavioralStats["std_dev_login_interval"] = 0
		commonPatterns["most_common_location"] = ""
		commonPatterns["most_common_device"] = ""
		return behavioralStats, commonPatterns
	}

	var totalTime float64
	var timeIntervals []float64
	locationCounts := make(map[string]int)
	deviceCounts := make(map[string]int)

	// Iterate over login history to compute intervals and common patterns
	for i := 1; i < len(logins); i++ {
		timeDiff := logins[i-1].CreatedAt.Sub(logins[i].CreatedAt).Seconds()
		timeIntervals = append(timeIntervals, timeDiff)
		totalTime += timeDiff

		locationCounts[logins[i].Location]++
		deviceCounts[logins[i].DeviceID]++
	}

	// Compute average login interval
	averageInterval := totalTime / float64(len(timeIntervals))
	behavioralStats["average_login_interval"] = averageInterval

	// Compute standard deviation of login intervals (for proper Z-score)
	behavioralStats["std_dev_login_interval"] = calculateStandardDeviation(timeIntervals, averageInterval)

	// Find most common location & device
	commonPatterns["most_common_location"] = getMostCommonKey(locationCounts)
	commonPatterns["most_common_device"] = getMostCommonKey(deviceCounts)

	return behavioralStats, commonPatterns
}

// Function: Compute Standard Deviation
func calculateStandardDeviation(data []float64, mean float64) float64 {
	if len(data) == 0 {
		return 0
	}
	var sumSquaredDiffs float64
	for _, value := range data {
		sumSquaredDiffs += math.Pow(value-mean, 2)
	}
	return math.Sqrt(sumSquaredDiffs / float64(len(data)))
}

// Helper Function: Get Most Common Key from a Map
func getMostCommonKey(counts map[string]int) string {
	maxCount := 0
	mostCommon := ""
	for key, count := range counts {
		if count > maxCount {
			maxCount = count
			mostCommon = key
		}
	}
	return mostCommon
}

// Compute Risk Score based on login behavior
func ComputeRiskScore(attempt *models.LoginAttempt, lastLogin *models.LoginAttempt, behavioralStats map[string]float64, commonPatterns map[string]string) (int, []string) {
	riskScore := 0
	alertMessages := []string{}

	if lastLogin != nil {
		// **GeoIP Analysis**
		if lastLogin.Location != attempt.Location {
			distance, err := utils.CalculateGeoDistance(lastLogin.Location, attempt.Location)
			if err == nil {
				attempt.DistanceFromLast = distance
				if distance > 5000 {
					riskScore += 30
					alertMessages = append(alertMessages, "Unusual location detected")
				} else if distance > 1000 {
					riskScore += 15
				}
			}
		}

		// **OTP Replay Attack**
		if lastLogin.OTPCodeHash == attempt.OTPCodeHash {
			attempt.OTPReplayDetected = true
			riskScore += 40
			alertMessages = append(alertMessages, "OTP replay detected")
		}

		// **Device Mismatch**
		if attempt.DeviceID != commonPatterns["most_common_device"] {
			attempt.DeviceMismatch = true
			riskScore += 25
			alertMessages = append(alertMessages, "Login from a new device")
		}

		// **Time-Based Attack Detection**
		if behavioralStats["average_login_interval"] > 0 {
			timeDiff := time.Since(lastLogin.CreatedAt).Seconds()
			zScore := (timeDiff - behavioralStats["average_login_interval"]) / behavioralStats["std_dev_login_interval"]
			if zScore > 2.0 {
				riskScore += 20
				alertMessages = append(alertMessages, "Unusual login time detected")
			}
		}
	}

	return riskScore, alertMessages
}

// Perform Network Analysis (Parallel)
func (s *PhishingService) PerformNetworkAnalysis(ctx context.Context, attempt *models.LoginAttempt, alertMessages *[]string) int {
	riskScore := 0
	var wg sync.WaitGroup
	wg.Add(3)

	// **High-Frequency Login Detection**
	go func() {
		defer wg.Done()
		loginCount, err := s.Repo.CountLoginsInLastHour(ctx, attempt.UserID)
		if err == nil && loginCount > 5 {
			riskScore += 20
			*alertMessages = append(*alertMessages, "High login frequency detected")
		}
	}()

	// **Multiple IPs in Short Duration**
	go func() {
		defer wg.Done()
		uniqueIPCount, err := s.Repo.CountUniqueIPsInLastHour(ctx, attempt.UserID)
		if err == nil && uniqueIPCount > 2 {
			riskScore += 20
			*alertMessages = append(*alertMessages, "Multiple IPs detected")
		}
	}()

	// **Network Reputation Analysis**
	go func() {
		defer wg.Done()
		if utils.CheckIPReputation(attempt.IPAddress) == "malicious" {
			riskScore += 50
			*alertMessages = append(*alertMessages, "IP flagged as malicious")
		}
		if utils.IsVPN(attempt.IPAddress) {
			riskScore += 15
			*alertMessages = append(*alertMessages, "VPN detected")
		}
		if utils.IsTorExitNode(attempt.IPAddress) {
			riskScore += 30
			*alertMessages = append(*alertMessages, "Tor network detected")
		}
	}()

	wg.Wait()
	return riskScore
}

// Send Security Alerts
func SendSecurityAlerts(attempt *models.LoginAttempt, riskScore int, alertMessages []string) {
	alertMessage := fmt.Sprintf("**Phishing Alert!** User: %s, IP: %s, Device: %s, Location: %s.\n🔹 Risk Score: %d\n🔹 Issues: %v",
		attempt.UserID, attempt.IPAddress, attempt.DeviceID, attempt.Location, riskScore, alertMessages)

	go utils.SendSlackAlert(alertMessage)
	go utils.SendEmailAlert("Security Alert", alertMessage)
}
