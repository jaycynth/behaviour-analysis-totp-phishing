package models

import "time"

type DeviceMetadata struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    string    `gorm:"index;not null" json:"user_id"`
	DeviceID  string    `gorm:"index;not null" json:"device_id"`
	OSVersion string    `json:"os_version"`
	UserAgent string    `json:"user_agent"`
	PublicIP  string    `json:"public_ip"`
	Timestamp time.Time `gorm:"autoCreateTime" json:"timestamp"`
}

func (DeviceMetadata) TableName() string {
	return "device_metadata"
}
