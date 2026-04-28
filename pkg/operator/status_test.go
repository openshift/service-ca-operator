package operator

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func newTestOperator(t *testing.T) *serviceCAOperator {
	t.Setenv(operatorVersionEnvName, "4.21.0")
	return &serviceCAOperator{
		versionGetter: status.NewVersionGetter(),
	}
}

func makeDeployment(name string, generation, observedGeneration int64, replicas, updatedReplicas, availableReplicas int32) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Generation: generation,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
		},
		Status: appsv1.DeploymentStatus{
			Replicas:           replicas,
			UpdatedReplicas:    updatedReplicas,
			AvailableReplicas:  availableReplicas,
			ObservedGeneration: observedGeneration,
		},
	}
}

func TestIsDeploymentStatusAvailable(t *testing.T) {
	tests := []struct {
		name   string
		deploy appsv1.Deployment
		expect bool
	}{
		{
			name:   "available replicas present",
			deploy: makeDeployment("test", 1, 1, 1, 1, 1),
			expect: true,
		},
		{
			name:   "no available replicas",
			deploy: makeDeployment("test", 1, 1, 1, 1, 0),
			expect: false,
		},
		{
			name: "some but not all replicas available",
			deploy: func() appsv1.Deployment {
				d := makeDeployment("test", 1, 1, 3, 3, 1)
				d.Spec.Replicas = ptr.To[int32](3)
				return d
			}(),
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDeploymentStatusAvailable(tt.deploy)
			if got != tt.expect {
				t.Errorf("isDeploymentStatusAvailable() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestIsDeploymentStatusAvailableAndUpdated(t *testing.T) {
	tests := []struct {
		name   string
		deploy appsv1.Deployment
		expect bool
	}{
		{
			name:   "fully available and updated",
			deploy: makeDeployment("test", 1, 1, 1, 1, 1),
			expect: true,
		},
		{
			name:   "no available replicas",
			deploy: makeDeployment("test", 1, 1, 1, 1, 0),
			expect: false,
		},
		{
			name:   "generation not yet observed",
			deploy: makeDeployment("test", 2, 1, 1, 1, 1),
			expect: false,
		},
		{
			name:   "updated replicas mismatch",
			deploy: makeDeployment("test", 1, 1, 2, 1, 1),
			expect: false,
		},
		{
			name: "some but not all replicas available, all updated",
			deploy: func() appsv1.Deployment {
				d := makeDeployment("test", 1, 1, 3, 3, 1)
				d.Spec.Replicas = ptr.To[int32](3)
				return d
			}(),
			expect: true,
		},
		{
			name: "some but not all replicas available, not all updated",
			deploy: func() appsv1.Deployment {
				d := makeDeployment("test", 1, 1, 3, 2, 1)
				d.Spec.Replicas = ptr.To[int32](3)
				return d
			}(),
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDeploymentStatusAvailableAndUpdated(tt.deploy)
			if got != tt.expect {
				t.Errorf("isDeploymentStatusAvailableAndUpdated() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestIsDeploymentStatusComplete(t *testing.T) {
	tests := []struct {
		name   string
		deploy appsv1.Deployment
		expect bool
	}{
		{
			name:   "fully complete",
			deploy: makeDeployment("test", 1, 1, 1, 1, 1),
			expect: true,
		},
		{
			name:   "not all replicas available",
			deploy: makeDeployment("test", 1, 1, 1, 1, 0),
			expect: false,
		},
		{
			name:   "generation not yet observed",
			deploy: makeDeployment("test", 2, 1, 1, 1, 1),
			expect: false,
		},
		{
			name: "rolling update in progress - not all pods updated",
			deploy: func() appsv1.Deployment {
				d := makeDeployment("test", 1, 1, 2, 1, 2)
				d.Spec.Replicas = ptr.To[int32](2)
				return d
			}(),
			expect: false,
		},
		{
			name:   "extra replicas still terminating",
			deploy: makeDeployment("test", 1, 1, 2, 1, 1),
			expect: false,
		},
		{
			name: "nil spec replicas defaults to 1",
			deploy: func() appsv1.Deployment {
				d := makeDeployment("test", 1, 1, 1, 1, 1)
				d.Spec.Replicas = nil
				return d
			}(),
			expect: true,
		},
		{
			name: "some but not all replicas available",
			deploy: func() appsv1.Deployment {
				d := makeDeployment("test", 1, 1, 3, 3, 1)
				d.Spec.Replicas = ptr.To[int32](3)
				return d
			}(),
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDeploymentStatusComplete(tt.deploy)
			if got != tt.expect {
				t.Errorf("isDeploymentStatusComplete() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestSyncStatus(t *testing.T) {
	defaultTargets := sets.New("service-ca")

	tests := []struct {
		name              string
		targets           sets.Set[string]
		deployments       []appsv1.Deployment
		expectProgressing operatorv1.ConditionStatus
		expectAvailable   operatorv1.ConditionStatus
		expectVersionSet  bool
		expectReason      string
	}{
		{
			name:              "fully complete deployment",
			deployments:       []appsv1.Deployment{makeDeployment("service-ca", 1, 1, 1, 1, 1)},
			expectProgressing: operatorv1.ConditionFalse,
			expectAvailable:   operatorv1.ConditionTrue,
			expectVersionSet:  true,
			expectReason:      "ManagedDeploymentsCompleteAndUpdated",
		},
		{
			name:              "no available replicas",
			deployments:       []appsv1.Deployment{makeDeployment("service-ca", 1, 1, 1, 1, 0)},
			expectProgressing: operatorv1.ConditionTrue,
			// TODO: Available should be False when no replicas are available.
			// The fallthrough in syncStatus overwrites the earlier setAvailableFalse.
			expectAvailable:  operatorv1.ConditionTrue,
			expectVersionSet: false,
			expectReason:     "ManagedDeploymentsAvailable",
		},
		{
			name:              "generation mismatch - not yet observed",
			deployments:       []appsv1.Deployment{makeDeployment("service-ca", 2, 1, 1, 1, 1)},
			expectProgressing: operatorv1.ConditionTrue,
			expectAvailable:   operatorv1.ConditionTrue,
			expectVersionSet:  false,
			expectReason:      "ManagedDeploymentsAvailable",
		},
		{
			name:              "recreate rollout - replicas scaled down",
			deployments:       []appsv1.Deployment{makeDeployment("service-ca", 1, 1, 0, 0, 0)},
			expectProgressing: operatorv1.ConditionTrue,
			// TODO: Available should be False when all replicas are scaled down.
			expectAvailable:  operatorv1.ConditionTrue,
			expectVersionSet: false,
			expectReason:     "ManagedDeploymentsAvailable",
		},
		{
			name:              "missing deployment",
			deployments:       []appsv1.Deployment{},
			expectProgressing: operatorv1.ConditionTrue,
			expectAvailable:   operatorv1.ConditionFalse,
			expectVersionSet:  false,
			expectReason:      "ManagedDeploymentsNotFound",
		},
		{
			name: "deployment being deleted",
			deployments: []appsv1.Deployment{
				func() appsv1.Deployment {
					d := makeDeployment("service-ca", 1, 1, 1, 1, 1)
					now := metav1.Now()
					d.DeletionTimestamp = &now
					return d
				}(),
			},
			expectProgressing: operatorv1.ConditionTrue,
			// TODO: Available should be False when the deployment is being deleted.
			expectAvailable:  operatorv1.ConditionTrue,
			expectVersionSet: false,
			expectReason:     "ManagedDeploymentsAvailable",
		},
		{
			name:              "available and updated but not all replicas available yet",
			deployments:       []appsv1.Deployment{makeDeployment("service-ca", 1, 1, 2, 2, 1)},
			expectProgressing: operatorv1.ConditionTrue,
			expectAvailable:   operatorv1.ConditionTrue,
			expectVersionSet:  true,
			expectReason:      "ManagedDeploymentsAvailableAndUpdated",
		},
		{
			name:              "available but old replicas still exist",
			deployments:       []appsv1.Deployment{makeDeployment("service-ca", 1, 1, 2, 1, 1)},
			expectProgressing: operatorv1.ConditionTrue,
			expectAvailable:   operatorv1.ConditionTrue,
			expectVersionSet:  false,
			expectReason:      "ManagedDeploymentsAvailable",
		},
		{
			name: "some replicas available, all updated, not yet complete",
			deployments: []appsv1.Deployment{
				func() appsv1.Deployment {
					d := makeDeployment("service-ca", 1, 1, 3, 3, 1)
					d.Spec.Replicas = ptr.To[int32](3)
					return d
				}(),
			},
			expectProgressing: operatorv1.ConditionTrue,
			expectAvailable:   operatorv1.ConditionTrue,
			expectVersionSet:  true,
			expectReason:      "ManagedDeploymentsAvailableAndUpdated",
		},
		{
			name: "some replicas available, not all updated",
			deployments: []appsv1.Deployment{
				func() appsv1.Deployment {
					d := makeDeployment("service-ca", 1, 1, 3, 2, 1)
					d.Spec.Replicas = ptr.To[int32](3)
					return d
				}(),
			},
			expectProgressing: operatorv1.ConditionTrue,
			expectAvailable:   operatorv1.ConditionTrue,
			expectVersionSet:  false,
			expectReason:      "ManagedDeploymentsAvailable",
		},
		{
			name:    "two targets, both complete",
			targets: sets.New("deploy-a", "deploy-b"),
			deployments: []appsv1.Deployment{
				makeDeployment("deploy-a", 1, 1, 1, 1, 1),
				makeDeployment("deploy-b", 1, 1, 1, 1, 1),
			},
			expectProgressing: operatorv1.ConditionFalse,
			expectAvailable:   operatorv1.ConditionTrue,
			expectVersionSet:  true,
			expectReason:      "ManagedDeploymentsCompleteAndUpdated",
		},
		{
			name:    "two targets, one complete and one unavailable",
			targets: sets.New("deploy-a", "deploy-b"),
			deployments: []appsv1.Deployment{
				makeDeployment("deploy-a", 1, 1, 1, 1, 1),
				makeDeployment("deploy-b", 1, 1, 1, 1, 0),
			},
			expectProgressing: operatorv1.ConditionTrue,
			// TODO: Available should be False when a deployment has no available replicas.
			expectAvailable:  operatorv1.ConditionTrue,
			expectVersionSet: false,
			expectReason:     "ManagedDeploymentsAvailable",
		},
		{
			name:    "two targets, one complete and one updating",
			targets: sets.New("deploy-a", "deploy-b"),
			deployments: []appsv1.Deployment{
				makeDeployment("deploy-a", 1, 1, 1, 1, 1),
				makeDeployment("deploy-b", 2, 1, 1, 1, 1),
			},
			expectProgressing: operatorv1.ConditionTrue,
			expectAvailable:   operatorv1.ConditionTrue,
			expectVersionSet:  false,
			expectReason:      "ManagedDeploymentsAvailable",
		},
		{
			name:    "two targets, one missing",
			targets: sets.New("deploy-a", "deploy-b"),
			deployments: []appsv1.Deployment{
				makeDeployment("deploy-a", 1, 1, 1, 1, 1),
			},
			expectProgressing: operatorv1.ConditionTrue,
			expectAvailable:   operatorv1.ConditionFalse,
			expectVersionSet:  false,
			expectReason:      "ManagedDeploymentsNotFound",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := newTestOperator(t)
			sc := &operatorv1.ServiceCA{}
			depList := &appsv1.DeploymentList{Items: tt.deployments}

			targets := tt.targets
			if targets == nil {
				targets = defaultTargets
			}
			op.syncStatus(sc, depList, targets)

			progressing := v1helpers.FindOperatorCondition(sc.Status.Conditions, operatorv1.OperatorStatusTypeProgressing)
			if progressing == nil {
				t.Fatal("expected Progressing condition to be set")
			}
			if progressing.Status != tt.expectProgressing {
				t.Errorf("Progressing: got %s, want %s (reason=%s, message=%s)",
					progressing.Status, tt.expectProgressing, progressing.Reason, progressing.Message)
			}
			if progressing.Reason != tt.expectReason {
				t.Errorf("Progressing reason: got %q, want %q", progressing.Reason, tt.expectReason)
			}

			available := v1helpers.FindOperatorCondition(sc.Status.Conditions, operatorv1.OperatorStatusTypeAvailable)
			if available == nil {
				t.Fatal("expected Available condition to be set")
			}
			if available.Status != tt.expectAvailable {
				t.Errorf("Available: got %s, want %s (reason=%s, message=%s)",
					available.Status, tt.expectAvailable, available.Reason, available.Message)
			}

			versions := op.versionGetter.GetVersions()
			_, versionSet := versions["operator"]
			if versionSet != tt.expectVersionSet {
				t.Errorf("version set: got %v, want %v", versionSet, tt.expectVersionSet)
			}
		})
	}
}
