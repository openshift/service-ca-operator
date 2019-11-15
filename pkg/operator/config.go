package operator

import (
	"encoding/json"
	"time"
)

type unsupportedServiceCAConfig struct {
	CAConfig caConfig `json:"caConfig"`

	TimeBasedRotation timeBasedRotationConfig `json:"timeBasedRotation"`

	ForceRotation forceRotationConfig `json:"forceRotation"`
}

type caConfig struct {
	// validityDurationForTesting determines how long a new signing CA
	// will be valid for from the time that it is generated. It should
	// only be used for testing purposes and is not intended for
	// production use. If unspecified or 0, the CA will be valid for 1
	// year.
	// +optional
	ValidityDurationForTesting time.Duration `json:"validityDurationForTesting"`
}

type timeBasedRotationConfig struct {
	// enabled determines whether automatic rotation will occur when the signing CA
	// has less than a minimum validity duration.
	// +optional
	Enabled bool `json:"enabled"`
}

type forceRotationConfig struct {
	// reason indicates why a rotation of the signing CA should be forced. If the
	// reason is not empty and has not been recorded as an annotation on the signing
	// secret, the rotation of the signing CA will be triggered at most once.
	// +optional
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
func RawUnsupportedServiceCAConfig(enabled bool, reason string, duration time.Duration) ([]byte, error) {
	config := &unsupportedServiceCAConfig{
		CAConfig: caConfig{
			ValidityDurationForTesting: duration,
		},
		TimeBasedRotation: timeBasedRotationConfig{
			Enabled: enabled,
		},
		ForceRotation: forceRotationConfig{
			Reason: reason,
		},
	}
	return json.Marshal(config)
}
