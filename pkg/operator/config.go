package operator

import (
	"encoding/json"
)

type unsupportedServiceCAConfig struct {
	TimeBasedRotation timeBasedRotationConfig `json:"timeBasedRotation"`

	ForceRotation forceRotationConfig `json:"forceRotation"`
}

type timeBasedRotationConfig struct {
	Enabled bool `json:"enabled"`
}

type forceRotationConfig struct {
	Reason string `json:"reason"`
}

// loadUnsupportedServiceCAConfig loads an unsupportedServiceCAConfig from raw bytes.
func loadUnsupportedServiceCAConfig(raw []byte) (unsupportedServiceCAConfig, error) {
	serviceCAConfig := unsupportedServiceCAConfig{}
	if len(raw) == 0 {
		return serviceCAConfig, nil
	}
	err := json.Unmarshal(raw, &serviceCAConfig)
	return serviceCAConfig, err
}

// RawUnsupportedServiceCAConfig returns the raw value of the operator field
// UnsupportedConfigOverrides for whether time-based rotation is enabled and the
// given force rotation reason.
func RawUnsupportedServiceCAConfig(enabled bool, reason string) ([]byte, error) {
	config := &unsupportedServiceCAConfig{
		TimeBasedRotation: timeBasedRotationConfig{
			Enabled: enabled,
		},
		ForceRotation: forceRotationConfig{
			Reason: reason,
		},
	}
	return json.Marshal(config)
}
