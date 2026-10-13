package operator

import (
	"encoding/json"
	"time"
)

type unsupportedServiceCAConfig struct {
	CAConfig caConfig `json:"caConfig"`

	ForceRotation forceRotationConfig `json:"forceRotation"`
}

type caConfig struct {
	// validityDurationForTesting determines how long a new signing CA
	// will be valid for from the time that it is generated. It should
	// only be used for testing purposes and is not intended for
	// production use. If unspecified or 0, the CA will be valid for 26
	// months.
	// +optional
	ValidityDurationForTesting time.Duration `json:"validityDurationForTesting"`
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

// RawUnsupportedServiceCAConfig returns the raw value of the operator
// field UnsupportedConfigOverrides for the given force rotation
// reason.
func RawUnsupportedServiceCAConfig(reason string, duration time.Duration) ([]byte, error) {
	config := &unsupportedServiceCAConfig{
		CAConfig: caConfig{
			ValidityDurationForTesting: duration,
		},
		ForceRotation: forceRotationConfig{
			Reason: reason,
		},
	}
	return json.Marshal(config)
}
