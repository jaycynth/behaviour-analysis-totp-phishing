package handlers

import (
	"encoding/json"
	"fmt"
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
		fmt.Printf("Error decoding JSON: %v\n", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields in metadata
	if metadata.DeviceID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Call service to sync metadata
	if err := h.service.SyncDeviceMetadata(&metadata); err != nil {
		http.Error(w, "Failed to sync device", http.StatusInternalServerError)
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Device synced successfully"})
}
