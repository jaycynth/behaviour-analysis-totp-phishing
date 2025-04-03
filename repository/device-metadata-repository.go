package repository

import (
	"github.com/jaycynth/behaviour-analysis-totp-phishing/models"
	"gorm.io/gorm"
)

type DeviceRepository interface {
	SaveDeviceMetadata(metadata *models.DeviceMetadata) (*models.DeviceMetadata, error)
	GetDeviceByID(deviceID string) (*models.DeviceMetadata, error)
}

type DeviceRepositoryImpl struct {
	db *gorm.DB
}

func NewDeviceRepository(db *gorm.DB) DeviceRepository {
	return &DeviceRepositoryImpl{db: db}
}

func (r *DeviceRepositoryImpl) SaveDeviceMetadata(metadata *models.DeviceMetadata) (*models.DeviceMetadata, error) {
	if err := r.db.Create(metadata).Error; err != nil {
		return nil, err
	}
	return metadata, nil
}

func (r *DeviceRepositoryImpl) GetDeviceByID(deviceID string) (*models.DeviceMetadata, error) {
	var metadata models.DeviceMetadata
	result := r.db.Where("device_id = ?", deviceID).First(&metadata)
	if result.Error != nil {
		return nil, result.Error
	}
	return &metadata, nil
}
