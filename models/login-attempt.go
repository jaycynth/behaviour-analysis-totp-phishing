package models

import (
	"time"

	"gorm.io/gorm"
)

type LoginAttempt struct {
	ID                  uint           `gorm:"primaryKey" json:"id"`
	UserID              string         `gorm:"index" json:"user_id"`
	IPAddress           string         `gorm:"index" json:"ip_address"`
	DeviceID            string         `gorm:"index" json:"device_id"`
	Location            string         `json:"location"`
	UserAgent           string         `json:"user_agent"`
	OTPCodeHash         string         `json:"-"`
	Success             bool           `json:"success"`
	DistanceFromLast    float64        `json:"distance_from_last"`
	LoginVelocity       float64        `json:"login_velocity"`
	IsPhishingRisk      bool           `json:"is_phishing_risk"`
	DeviceMismatch      bool           `json:"device_mismatch"`
	OTPReplayDetected   bool           `json:"otp_replay_detected"`
	LoginFrequencyHigh  bool           `json:"login_frequency_high"`
	MultipleIPsDetected bool           `json:"multiple_ips_detected"`
	CreatedAt           time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt           time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt           gorm.DeletedAt `gorm:"index" json:"-"`
}

func (LoginAttempt) TableName() string {
	return "login_attempts"
}
