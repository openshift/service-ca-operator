package metrics

import (
	"time"

	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

var expiryTime = metrics.NewGauge(&metrics.GaugeOpts{
	Name: "service_ca_expiry_time_seconds",
	Help: "Reports the expiry time of service CA used in the cluster.",
})

func init() {
	legacyregistry.MustRegister(expiryTime)
}

func SetCAExpiry(notAfter time.Time) {
	expiryTime.Set(float64(notAfter.Unix()))
}
