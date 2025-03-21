package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

var (
	geoDB       *geoip2.Reader
	geoInitOnce sync.Once
	geoCache    sync.Map // Caching country lookups
)

// Initialize GeoIP database once
func InitGeoIP(dbPath string) error {
	var err error
	geoInitOnce.Do(func() {
		geoDB, err = geoip2.Open(dbPath)
		if err != nil {
			log.Fatalf("[ERROR] Failed to load GeoIP database: %v", err)
		}
	})
	if err == nil {
		fmt.Println("[INFO] GeoIP database initialized successfully!")
	}
	return err
}

// GetCountry retrieves the country name from an IP address
func GetCountry(ip string) (string, error) {
	if geoDB == nil {
		return "Unknown", fmt.Errorf("GeoIP database not initialized")
	}

	// Check cache first
	if country, found := geoCache.Load(ip); found {
		return country.(string), nil
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "Unknown", fmt.Errorf("invalid IP address: %s", ip)
	}

	record, err := geoDB.City(parsedIP)
	if err != nil {
		return "Unknown", fmt.Errorf("GeoIP lookup error: %v", err)
	}

	country := record.Country.Names["en"]
	if country == "" {
		country = "Unknown"
	}

	// Store in cache
	geoCache.Store(ip, country)

	return country, nil
}

// CalculateGeoDistance computes the distance between two locations (in KM) using Haversine formula
func CalculateGeoDistance(loc1, loc2 string) (float64, error) {
	lat1, lon1, err1 := GetLatLon(loc1)
	lat2, lon2, err2 := GetLatLon(loc2)

	if err1 != nil || err2 != nil {
		log.Printf("[WARNING] Failed to retrieve coordinates for %s or %s", loc1, loc2)
		return -1, fmt.Errorf("invalid coordinates for distance calculation")
	}

	const EarthRadius = 6371 // Earth's radius in kilometers
	dLat := toRadians(lat2 - lat1)
	dLon := toRadians(lon2 - lon1)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(toRadians(lat1))*math.Cos(toRadians(lat2))*
			math.Sin(dLon/2)*math.Sin(dLon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return EarthRadius * c, nil
}

// Converts degrees to radians
func toRadians(deg float64) float64 {
	return deg * (math.Pi / 180)
}

// GetLatLon fetches latitude and longitude using OpenStreetMap API (with caching)
var locationCache sync.Map

func GetLatLon(location string) (float64, float64, error) {
	// Check cache first
	if cached, found := locationCache.Load(location); found {
		coords := cached.([2]float64)
		return coords[0], coords[1], nil
	}

	apiURL := fmt.Sprintf("https://nominatim.openstreetmap.org/search?q=%s&format=json", location)
	resp, err := http.Get(apiURL)
	if err != nil {
		return 0, 0, fmt.Errorf("[ERROR] OpenStreetMap API error: %v", err)
	}
	defer resp.Body.Close()

	var results []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil || len(results) == 0 {
		return 0, 0, fmt.Errorf("[ERROR] Invalid response from GeoAPI")
	}

	lat, err1 := strconv.ParseFloat(results[0]["lat"].(string), 64)
	lon, err2 := strconv.ParseFloat(results[0]["lon"].(string), 64)

	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("[ERROR] Failed to parse coordinates")
	}

	// Store in cache
	locationCache.Store(location, [2]float64{lat, lon})

	return lat, lon, nil
}

func GetGeoIP(ip string) (string, error) {
	return GetCountry(ip) // Uses cached function
}
