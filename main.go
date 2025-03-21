package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	database "github.com/jaycynth/behaviour-analysis-totp-phishing/config"
	"github.com/jaycynth/behaviour-analysis-totp-phishing/handlers"
	"github.com/jaycynth/behaviour-analysis-totp-phishing/repository"
	"github.com/jaycynth/behaviour-analysis-totp-phishing/services"
	"github.com/jaycynth/behaviour-analysis-totp-phishing/utils"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found. Using default environment variables.")
	}

	// Initialize database
	database.InitDB()
	db := database.GetDB()

	//Initialize redis
	database.InitRedis()
	redis := database.GetRedisClient()

	// Initialize GeoIP database
	geoDBPath := os.Getenv("GEOIP_DB_PATH")
	if geoDBPath == "" {
		geoDBPath = "/data/GeoLite2-Country.mmdb"
	}
	if err := utils.InitGeoIP(geoDBPath); err != nil {
		log.Fatalf("Failed to initialize GeoIP database: %v", err)
	}

	loginHandler := handlers.NewLoginHandler(
		services.NewPhishingService(
			repository.NewLoginAttemptRepo(db, redis),
		),
	)

	deviceHandler := handlers.NewDeviceHandler(
		services.NewDeviceService(
			repository.NewDeviceRepository(db),
		),
	)

	// Create router
	router := mux.NewRouter()

	// Define routes
	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/login", loginHandler.HandleLogin).Methods(http.MethodPost)
	apiRouter.HandleFunc("/sync-device", deviceHandler.HandleSyncDevice).Methods(http.MethodPost)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	log.Println("Server is running on port", port)

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exited gracefully.")
}
