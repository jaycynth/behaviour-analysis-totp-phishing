package config

import (
	"context"
	"log"

	"github.com/redis/go-redis/v9"
)

var (
	ctx         = context.Background()
	redisClient *redis.Client
)

func NewRedisClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
}

func InitRedis() {
	redisClient = NewRedisClient()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Could not connect to Redis: %v", err)
	}
	log.Println("Connected to Redis successfully!")
}

func GetRedisClient() *redis.Client {
	if redisClient == nil {
		log.Fatal("Redis client is not initialized. Call InitRedis first.")
	}
	return redisClient
}
