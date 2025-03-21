package repository

import (
	"context"
	"errors"
	"log"
	"strconv"
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

// Get Last Login
func (r *LoginAttemptRepository) GetLastLogin(ctx context.Context, userID string, limit ...int32) ([]*models.LoginAttempt, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}

	// Set default limit if not provided
	defaultLimit := int32(1)
	if len(limit) > 0 {
		defaultLimit = limit[0]
	}

	var lastLogins []*models.LoginAttempt
	err := r.DB.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(int(defaultLimit)).
		Find(&lastLogins).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Printf("no login attempts found for user %s", userID)
		return nil, nil
	}
	return lastLogins, err
}

// Count Logins in Last Hour
func (r *LoginAttemptRepository) CountLoginsInLastHour(ctx context.Context, userID string) (int64, error) {
	if userID == "" {
		return 0, errors.New("user ID cannot be empty")
	}

	mainCacheKey := "logins:last_60m:" + userID
	backupCacheKey := "logins:last_30m:" + userID
	var count int64

	// Use Redis Pipelining for Faster Cache Fetching
	pipe := r.Redis.Pipeline()
	mainCache := pipe.Get(ctx, mainCacheKey)
	backupCache := pipe.Get(ctx, backupCacheKey)
	_, _ = pipe.Exec(ctx)

	// Check Main Cache
	if mainCount, err := mainCache.Result(); err == nil {
		if parsed, err := strconv.ParseInt(mainCount, 10, 64); err == nil {
			return parsed, nil
		}
	}

	// Check Backup Cache
	if backupCount, err := backupCache.Result(); err == nil {
		if parsed, err := strconv.ParseInt(backupCount, 10, 64); err == nil {
			return parsed, nil
		}
	}

	// Cache Miss → Fetch from Database
	if err := r.DB.WithContext(ctx).
		Model(&models.LoginAttempt{}).
		Where("user_id = ? AND created_at >= ?", userID, time.Now().UTC().Add(-1*time.Hour)).
		Count(&count).Error; err != nil {
		return 0, err
	}

	// Store in Redis Cache (Atomic)
	pipe.Set(ctx, mainCacheKey, count, time.Hour)
	pipe.Set(ctx, backupCacheKey, count, 30*time.Minute)
	_, _ = pipe.Exec(ctx)

	return count, nil
}

// Count Unique IPs in Last Hour (Prevents SQL Injection)
func (r *LoginAttemptRepository) CountUniqueIPsInLastHour(ctx context.Context, userID string) (int64, error) {
	if userID == "" {
		return 0, errors.New("user ID cannot be empty")
	}

	cacheKey := "unique_ips:last_hour:" + userID
	var count int64

	// Check Redis First
	if cachedCount, err := r.Redis.Get(ctx, cacheKey).Result(); err == nil {
		if parsed, err := strconv.ParseInt(cachedCount, 10, 64); err == nil {
			return parsed, nil
		}
	}

	// Cache Miss → Fetch from Database
	err := r.DB.WithContext(ctx).
		Model(&models.LoginAttempt{}).
		Where("user_id = ? AND created_at >= ?", userID, time.Now().UTC().Add(-1*time.Hour)).
		Distinct("ip_address").
		Count(&count).Error

	if err != nil {
		return 0, err
	}

	// Store in Redis
	_ = r.Redis.Set(ctx, cacheKey, count, time.Hour).Err()
	return count, nil
}
