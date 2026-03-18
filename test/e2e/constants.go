package e2e

import "time"

const (
	// rotationPollTimeout is used for operations that may take longer due to
	// cluster state changes (rotation, regeneration, etc.)
	rotationPollTimeout = 4 * time.Minute

	// rotationTimeout is the maximum time to wait for certificate rotation
	rotationTimeout = 5 * time.Minute

	// signingCertificateLifetime is the default lifetime for the signing CA certificate
	signingCertificateLifetime = 790 * 24 * time.Hour
)
