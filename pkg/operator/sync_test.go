package operator

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestShouldScheduleOnWorkers(t *testing.T) {
	tests := []struct {
		name   string
		infra  *configv1.Infrastructure
		expect bool
	}{
		{
			name: "ha topology",
			infra: &configv1.Infrastructure{
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.HighlyAvailableTopologyMode,
				},
			},
			expect: false,
		},
		{
			name: "non-ha topology",
			infra: &configv1.Infrastructure{
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.SingleReplicaTopologyMode,
				},
			},
			expect: false,
		},
		{
			name: "external topology",
			infra: &configv1.Infrastructure{
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.ExternalTopologyMode,
				},
			},
			expect: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := shouldScheduleOnWorkers(test.infra)
			if result != test.expect {
				t.Errorf("Unexpected result: %v", result)
			}
		})
	}
}
