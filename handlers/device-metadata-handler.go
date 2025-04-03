package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/jaycynth/behaviour-analysis-totp-phishing/models"
	"github.com/jaycynth/behaviour-analysis-totp-phishing/services"
)

type DeviceHandler struct {
	service *services.DeviceService
}

func NewDeviceHandler(service *services.DeviceService) *DeviceHandler {
	return &DeviceHandler{service: service}
}

func (h *DeviceHandler) HandleSyncDevice(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to prevent large payload attacks
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit

	var metadata models.DeviceMetadata

	// Decode JSON with strict validation
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		log.Printf("Error decoding JSON: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields in metadata
	if metadata.DeviceID == "" {
		log.Println("Validation error: Missing required fields in metadata")
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	log.Printf("Starting to sync device metadata for DeviceID: %s", metadata.DeviceID)

	if _, err := h.service.SyncDeviceMetadata(&metadata); err != nil {
		log.Printf("Error syncing device metadata for DeviceID %s: %v", metadata.DeviceID, err)
		http.Error(w, "Failed to sync device", http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully synced device metadata for DeviceID: %s", metadata.DeviceID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"message": "Device synced successfully"}); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Failed to send response", http.StatusInternalServerError)
	}
}
