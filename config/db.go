package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jaycynth/behaviour-analysis-totp-phishing/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	if dbHost == "" || dbPort == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		log.Fatal("Database environment variables are not set properly")
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		PrepareStmt:            true, // Caches prepared statements for efficiency
		SkipDefaultTransaction: true, // Improves performance for bulk inserts
	})
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	sqlDB, err := DB.DB()
	if err != nil {
		log.Fatalf("Failed to get database instance: %v", err)
	}

	// Set database connection pool settings for scalability
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	log.Println("Connected to the database successfully!")

	runMigrations()
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	if DB == nil {
		log.Fatal("Database connection is not initialized")
	}
	return DB
}

func runMigrations() {
	if err := DB.AutoMigrate(
		&models.DeviceMetadata{},
		&models.LoginAttempt{},
	); err != nil {
		log.Fatalf("Migration failed: %v", err)
	} else {
		log.Println("Database migration completed successfully")
	}
}
