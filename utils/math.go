package utils

import "math"

func Mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func StandardDeviation(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	mean := Mean(values)
	var sumSquaredDiff float64

	for _, v := range values {
		diff := v - mean
		sumSquaredDiff += diff * diff
	}

	return math.Sqrt(sumSquaredDiff / float64(len(values)))
}

func MostCommonKey[K comparable](counts map[K]int) K {
	var maxCount int
	var mostCommon K

	for key, count := range counts {
		if count > maxCount {
			maxCount = count
			mostCommon = key
		}
	}

	return mostCommon
}
