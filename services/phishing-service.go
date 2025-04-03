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

type BehavioralStats struct {
	AvgLoginInterval   float64
	StdDevInterval     float64
	MostCommonLocation string
	MostCommonDevice   string
}

func (s *PhishingService) DetectPhishing(ctx context.Context, attempt *models.LoginAttempt) error {
	tx := s.Repo.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			log.Printf("[ERROR] Panic recovered in DetectPhishing for user %s: %v", attempt.UserID, r)
		}
	}()

	// Fetch login history
	history, err := s.Repo.GetLastLogin(ctx, attempt.UserID, 50)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch login history for user %s: %v", attempt.UserID, err)
		tx.Rollback()
		return fmt.Errorf("error fetching login history: %w", err)
	}

	var lastLogin *models.LoginAttempt
	if len(history) > 0 {
		lastLogin = history[0] // Most recent login
	}

	// Compute behavioral stats
	behavioralStats := CalculateBehavioralStats(history)

	// Compute risk score based on heuristics
	riskScore, alertMessages, err := ComputeRiskScore(attempt, lastLogin, behavioralStats)
	if err != nil {
		log.Printf("[ERROR] Failed to compute risk score for user %s: %v", attempt.UserID, err)
		tx.Rollback()
		return err
	}

	// Perform additional network-based heuristics in parallel
	networkRisk, networkAnalysisResult, err := s.PerformNetworkAnalysis(ctx, attempt, &alertMessages)
	if err != nil {
		log.Printf("[ERROR] Network analysis failed for user %s: %v", attempt.UserID, err)
		tx.Rollback()
		return err
	}
	riskScore += networkRisk

	attempt.RiskScore = riskScore
	attempt.MultipleIPsDetected = networkAnalysisResult.UniqueIPCount > 2
	attempt.LoginFrequencyHigh = networkAnalysisResult.LoginCount > 5

	log.Printf("[RISK SCORE]  %s: %d", attempt.UserID, riskScore)

	// Trigger alerts if necessary
	if riskScore > 75 {
		attempt.IsPhishingRisk = true
		err := SendSecurityAlerts(attempt, riskScore, alertMessages)
		if err != nil {
			log.Printf("[ERROR] Failed to send security alerts for user %s: %v", attempt.UserID, err)
		}
	}

	// Save login attempt
	if err := tx.Create(attempt).Error; err != nil {
		log.Printf("[ERROR] Failed to save login attempt for user %s: %v", attempt.UserID, err)
		tx.Rollback()
		return fmt.Errorf("error saving login attempt: %w", err)
	}

	// Commit transaction safely
	if err := tx.Commit().Error; err != nil {
		log.Printf("[ERROR] Transaction commit failed for user %s: %v", attempt.UserID, err)
		tx.Rollback()
		return fmt.Errorf("transaction commit error: %w", err)
	}

	return nil
}

func CalculateBehavioralStats(logins []*models.LoginAttempt) *BehavioralStats {
	if len(logins) == 0 {
		return &BehavioralStats{}
	}

	var timeIntervals []float64
	locationCounts := make(map[string]int)
	deviceCounts := make(map[string]int)

	for i := 1; i < len(logins); i++ {
		timeDiff := logins[i-1].CreatedAt.Sub(logins[i].CreatedAt).Seconds()
		timeIntervals = append(timeIntervals, timeDiff)
		locationCounts[logins[i].Location]++
		deviceCounts[logins[i].DeviceID]++
	}

	return &BehavioralStats{
		AvgLoginInterval:   utils.Mean(timeIntervals),
		StdDevInterval:     utils.StandardDeviation(timeIntervals),
		MostCommonLocation: utils.MostCommonKey(locationCounts),
		MostCommonDevice:   utils.MostCommonKey(deviceCounts),
	}
}

func ComputeRiskScore(attempt *models.LoginAttempt, lastLogin *models.LoginAttempt, stats *BehavioralStats) (int, []string, error) {
	riskScore := 0
	alertMessages := []string{}

	if lastLogin == nil {
		return riskScore, alertMessages, nil
	}

	distance, err := utils.CalculateGeoDistance(lastLogin.Location, attempt.Location)
	if err == nil {
		attempt.DistanceFromLast = distance
		if distance > 5000 {
			riskScore += 30
			alertMessages = append(alertMessages, "Unusual location detected")
		} else if distance > 1000 {
			riskScore += 15
		}
	} else {
		log.Printf("[WARN] Failed to calculate geo distance: %v", err)
	}

	if lastLogin.OTPCodeHash == attempt.OTPCodeHash {
		attempt.OTPReplayDetected = true
		riskScore += 40
		alertMessages = append(alertMessages, "OTP replay detected")
	}

	if attempt.DeviceID != stats.MostCommonDevice {
		attempt.DeviceMismatch = true
		riskScore += 25
		alertMessages = append(alertMessages, "Login from a new device")
	}

	if stats.AvgLoginInterval > 0 && stats.StdDevInterval > 0 {
		timeDiff := time.Since(lastLogin.CreatedAt).Seconds()
		zScore := (timeDiff - stats.AvgLoginInterval) / stats.StdDevInterval
		if math.Abs(zScore) > 2.0 {
			riskScore += 20
			alertMessages = append(alertMessages, "Unusual login time detected")
		}
	}

	return riskScore, alertMessages, nil
}

func (s *PhishingService) PerformNetworkAnalysis(ctx context.Context, attempt *models.LoginAttempt, alertMessages *[]string) (int, *NetworkAnalysisResult, error) {
	riskScore := 0
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errList []error

	result := &NetworkAnalysisResult{}

	wg.Add(3)

	// High-Frequency Login Detection
	go func() {
		defer wg.Done()
		count, err := s.Repo.CountLoginsInLastHour(ctx, attempt.UserID)
		if err != nil {
			mu.Lock()
			errList = append(errList, err)
			mu.Unlock()
			return
		}
		mu.Lock()
		result.LoginCount = count
		if result.LoginCount > 5 {
			riskScore += 20
			*alertMessages = append(*alertMessages, "High login frequency detected")
		}
		mu.Unlock()
	}()

	// Multiple IPs in Short Duration
	go func() {
		defer wg.Done()
		count, err := s.Repo.CountUniqueIPsInLastHour(ctx, attempt.UserID)
		if err != nil {
			mu.Lock()
			errList = append(errList, err)
			mu.Unlock()
			return
		}
		mu.Lock()
		result.UniqueIPCount = count
		if result.UniqueIPCount > 2 {
			riskScore += 20
			*alertMessages = append(*alertMessages, "Multiple IPs detected")
		}
		mu.Unlock()
	}()

	// Network Reputation Analysis
	go func() {
		defer wg.Done()
		reputation := utils.CheckIPReputation(attempt.IPAddress)
		mu.Lock()
		result.IPReputation = reputation
		if reputation == "malicious" {
			riskScore += 50
			*alertMessages = append(*alertMessages, "IP flagged as malicious")
		}
		mu.Unlock()
	}()

	wg.Wait()

	if len(errList) > 0 {
		return riskScore, result, fmt.Errorf("network analysis errors: %v", errList)
	}

	return riskScore, result, nil
}

type NetworkAnalysisResult struct {
	LoginCount    int64
	UniqueIPCount int64
	IPReputation  string
}

func SendSecurityAlerts(attempt *models.LoginAttempt, riskScore int, alertMessages []string) error {
	alertMessage := fmt.Sprintf(`Dear User,

		We detected suspicious login activity on your account. Below are the details:
		User ID: %s  
		Login Attempt Time: %s  
		IP Address: %s  
		Geo-location: %s  
		Device Info: %s  
		Risk Level: High  
		Reason: %s  

		If this was not you, please reset your password immediately.

		Security Team`,
		attempt.UserID,
		attempt.CreatedAt.Format("2006-01-02 15:04:05 MST"),
		attempt.IPAddress,
		attempt.Location,
		attempt.DeviceID,
		alertMessages,
	)
	err := utils.SendEmailAlert("lokoc2623@gmail.com", alertMessage)
	return err
}
