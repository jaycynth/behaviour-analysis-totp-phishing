package config

// import "time"

// type Config struct {
// 	RiskThreshold     int           `json:"riskThreshold"`
// 	LoginHistoryLimit int           `json:"loginHistoryLimit"`
// 	AnalysisTimeout   time.Duration `json:"analysisTimeout"`
// 	CacheExpiration   time.Duration `json:"cacheExpiration"`
// 	RateLimitPerMin   int           `json:"rateLimitPerMinute"`
// 	IPReputation      struct {
// 		CacheTimeout  time.Duration `json:"cacheTimeout"`
// 		RetryAttempts int           `json:"retryAttempts"`
// 		RetryDelay    time.Duration `json:"retryDelay"`
// 	} `json:"ipReputation"`
// }

// func NewConfig() *Config {
// 	return &Config{
// 		RiskThreshold:     75,
// 		LoginHistoryLimit: 50,
// 		AnalysisTimeout:   5 * time.Second,
// 		CacheExpiration:   5 * time.Minute,
// 		RateLimitPerMin:   60,
// 		IPReputation: struct {
// 			CacheTimeout  time.Duration `json:"cacheTimeout"`
// 			RetryAttempts int           `json:"retryAttempts"`
// 			RetryDelay    time.Duration `json:"retryDelay"`
// 		}{
// 			CacheTimeout:  1 * time.Hour,
// 			RetryAttempts: 3,
// 			RetryDelay:    1 * time.Second,
// 		},
// 	}
// }
