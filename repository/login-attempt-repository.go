package repository

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/jaycynth/behaviour-analysis-totp-phishing/models"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// Struct Definition
type LoginAttemptRepository struct {
	DB    *gorm.DB
	Redis *redis.Client
}

func NewLoginAttemptRepo(db *gorm.DB, redis *redis.Client) *LoginAttemptRepository {
	return &LoginAttemptRepository{DB: db, Redis: redis}
}

// Save Login Attempt
func (r *LoginAttemptRepository) Save(ctx context.Context, login *models.LoginAttempt) error {
	switch {
	case login == nil:
		return errors.New("invalid login attempt: login cannot be nil")
	case login.UserID == "":
		return errors.New("invalid login attempt: user ID cannot be empty")
	case login.IPAddress == "":
		return errors.New("invalid login attempt: IP address cannot be empty")
	case login.DeviceID == "":
		return errors.New("invalid login attempt: device ID cannot be empty")
	}

	// Save to DB with transaction
	tx := r.DB.Begin()
	if err := tx.Create(login).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Update Cache Asynchronously (Non-Blocking)
	go r.UpdateLoginCache(ctx, login.UserID)

	tx.Commit()
	return nil
}

// Update Login Count in Cache
func (r *LoginAttemptRepository) UpdateLoginCache(ctx context.Context, userID string) {
	mainCacheKey := "logins:last_60m:" + userID
	backupCacheKey := "logins:last_30m:" + userID

	pipe := r.Redis.Pipeline()
	pipe.Incr(ctx, mainCacheKey)
	pipe.Expire(ctx, mainCacheKey, time.Hour)
	pipe.Incr(ctx, backupCacheKey)
	pipe.Expire(ctx, backupCacheKey, 30*time.Minute)
	_, _ = pipe.Exec(ctx)
}

func (r *LoginAttemptRepository) GetLastLogin(ctx context.Context, userID string, limit ...int32) ([]*models.LoginAttempt, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}

	// Set default limit if not provided
	defaultLimit := int32(1)
	if len(limit) > 0 {
		defaultLimit = limit[0]
	}

	cacheKey := "last_login:" + userID

	var lastLogins []*models.LoginAttempt

	// Attempt to fetch from Redis
	cachedData, err := r.Redis.Get(ctx, cacheKey).Result()
	if err == nil {
		if err := json.Unmarshal([]byte(cachedData), &lastLogins); err == nil {
			return lastLogins, nil
		}
	}

	// Cache Miss → Fetch from Database
	err = r.DB.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(int(defaultLimit)).
		Find(&lastLogins).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Printf("no login attempts found for user %s", userID)
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	cacheData, err := json.Marshal(lastLogins)
	if err == nil {
		_ = r.Redis.Set(ctx, cacheKey, cacheData, 10*time.Minute).Err()
	}

	return lastLogins, nil
}

func (r *LoginAttemptRepository) CountLoginsInLastHour(ctx context.Context, userID string) (int64, error) {
	if userID == "" {
		return 0, errors.New("user ID cannot be empty")
	}

	var count int64

	if err := r.DB.WithContext(ctx).
		Model(&models.LoginAttempt{}).
		Where("user_id = ? AND created_at >= ?", userID, time.Now().UTC().Add(-1*time.Hour)).
		Count(&count).Error; err != nil {
		return 0, err
	}

	return count, nil
}

func (r *LoginAttemptRepository) CountUniqueIPsInLastHour(ctx context.Context, userID string) (int64, error) {
	if userID == "" {
		return 0, errors.New("user ID cannot be empty")
	}

	var count int64

	err := r.DB.WithContext(ctx).
		Model(&models.LoginAttempt{}).
		Where("user_id = ? AND created_at >= ?", userID, time.Now().UTC().Add(-1*time.Hour)).
		Distinct("ip_address").
		Count(&count).Error

	if err != nil {
		return 0, err
	}

	return count, nil
}
