package operator

import (
	"os"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"sigs.k8s.io/yaml"
)

func requireRelatedObject(t *testing.T, refs []configv1.ObjectReference, want configv1.ObjectReference) {
	t.Helper()

	count := 0
	for _, ref := range refs {
		if ref == want {
			count++
		}
	}

	if count != 1 {
		t.Errorf("expected related object %+v exactly once, got %d", want, count)
	}
}

func TestClusterOperatorRelatedObjects(t *testing.T) {
	want := []configv1.ObjectReference{
		{Group: "operator.openshift.io", Resource: "servicecas", Name: "cluster"},
		{Resource: "namespaces", Name: "openshift-config"},
		{Resource: "namespaces", Name: "openshift-config-managed"},
		{Resource: "namespaces", Name: "openshift-service-ca-operator"},
		{Resource: "namespaces", Name: "openshift-service-ca"},
		{
			Group:    "rbac.authorization.k8s.io",
			Resource: "clusterrolebindings",
			Name:     "system:openshift:operator:service-ca-operator",
		},
	}

	refs := clusterOperatorRelatedObjects()

	for _, ref := range want {
		requireRelatedObject(t, refs, ref)
	}
}
func TestClusterOperatorManifestRelatedObjects(t *testing.T) {
	data, err := os.ReadFile("../../manifests/07_clusteroperator.yaml")
	if err != nil {
		t.Fatalf("read ClusterOperator manifest: %v", err)
	}

	var co configv1.ClusterOperator
	if err := yaml.Unmarshal(data, &co); err != nil {
		t.Fatalf("decode ClusterOperator manifest: %v", err)
	}
	if co.Kind != "ClusterOperator" || co.Name != "service-ca" {
		t.Fatalf("unexpected manifest identity: kind=%q name=%q", co.Kind, co.Name)
	}

	requireRelatedObject(t, co.Status.RelatedObjects, configv1.ObjectReference{
		Group:    "rbac.authorization.k8s.io",
		Resource: "clusterrolebindings",
		Name:     "system:openshift:operator:service-ca-operator",
	})
}
