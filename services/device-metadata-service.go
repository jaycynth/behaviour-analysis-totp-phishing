package services

import (
	"github.com/jaycynth/behaviour-analysis-totp-phishing/models"

	"github.com/jaycynth/behaviour-analysis-totp-phishing/repository"
)

type DeviceService struct {
	repo repository.DeviceRepository
}

func NewDeviceService(repo repository.DeviceRepository) *DeviceService {
	return &DeviceService{repo: repo}
}

func (s *DeviceService) SyncDeviceMetadata(metadata *models.DeviceMetadata) error {
	return s.repo.SaveDeviceMetadata(metadata)
}

func (s *DeviceService) GetDeviceMetadata(deviceID string) (*models.DeviceMetadata, error) {
	return s.repo.GetDeviceByID(deviceID)
}
