package e2e

import "time"

const (
	// rotationPollTimeout is used for operations that may take longer due to
	// cluster state changes (rotation, regeneration, etc.)
	rotationPollTimeout = 4 * time.Minute
)
