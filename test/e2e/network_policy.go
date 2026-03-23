package e2e

import (
	"context"
	"fmt"

	g "github.com/onsi/ginkgo/v2"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
)

var _ = g.Describe("[sig-service-ca] service-ca-operator network policies", func() {
	g.Context("operator-namespace-network-policies", func() {
		g.It("[Operator][Serial] should have network policies deployed in the operator namespace", func() {
			client, err := getKubeClient()
			if err != nil {
				g.Fail(fmt.Sprintf("error getting kube client: %v", err))
			}
			checkNetworkPoliciesExist(client, operatorclient.OperatorNamespace, []string{
				"service-ca-operator",
				"default-deny-all",
			})
		})
	})

	g.Context("controller-namespace-network-policies", func() {
		g.It("[Operator][Serial] should have network policies deployed in the controller namespace", func() {
			client, err := getKubeClient()
			if err != nil {
				g.Fail(fmt.Sprintf("error getting kube client: %v", err))
			}
			checkNetworkPoliciesExist(client, operatorclient.TargetNamespace, []string{
				"service-ca",
				"default-deny-all",
			})
		})
	})

	g.Context("operator-network-policy-spec", func() {
		g.It("[Operator][Serial] should allow metrics scraping on port 8443 and restrict other ingress in the operator namespace", func() {
			client, err := getKubeClient()
			if err != nil {
				g.Fail(fmt.Sprintf("error getting kube client: %v", err))
			}
			np, err := client.NetworkingV1().NetworkPolicies(operatorclient.OperatorNamespace).Get(
				context.TODO(), "service-ca-operator", metav1.GetOptions{},
			)
			if err != nil {
				g.Fail(fmt.Sprintf("failed to get NetworkPolicy service-ca-operator in %s: %v", operatorclient.OperatorNamespace, err))
			}
			checkServiceCANetworkPolicySpec(np, "app", "service-ca-operator")
		})
	})

	g.Context("controller-network-policy-spec", func() {
		g.It("[Operator][Serial] should allow metrics scraping on port 8443 and restrict other ingress in the controller namespace", func() {
			client, err := getKubeClient()
			if err != nil {
				g.Fail(fmt.Sprintf("error getting kube client: %v", err))
			}
			np, err := client.NetworkingV1().NetworkPolicies(operatorclient.TargetNamespace).Get(
				context.TODO(), "service-ca", metav1.GetOptions{},
			)
			if err != nil {
				g.Fail(fmt.Sprintf("failed to get NetworkPolicy service-ca in %s: %v", operatorclient.TargetNamespace, err))
			}
			checkServiceCANetworkPolicySpec(np, "app", "service-ca")
		})
	})
})

// checkNetworkPoliciesExist asserts that all named NetworkPolicies exist in the given namespace.
func checkNetworkPoliciesExist(client *kubernetes.Clientset, namespace string, names []string) {
	existing, err := client.NetworkingV1().NetworkPolicies(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		g.Fail(fmt.Sprintf("failed to list NetworkPolicies in %s: %v", namespace, err))
	}

	nameSet := make(map[string]bool, len(existing.Items))
	for _, np := range existing.Items {
		nameSet[np.Name] = true
	}

	for _, name := range names {
		if !nameSet[name] {
			g.Fail(fmt.Sprintf("expected NetworkPolicy %q to exist in namespace %s, but it was not found (found: %v)",
				name, namespace, existingNetworkPolicyNames(existing.Items)))
		}
	}
}

// checkServiceCANetworkPolicySpec validates that a service-ca allow policy:
// - selects pods by the expected label
// - allows ingress on TCP 8443 (metrics scraping)
// - allows egress on port 5353 (DNS)
// - declares both Ingress and Egress policyTypes
func checkServiceCANetworkPolicySpec(np *networkingv1.NetworkPolicy, labelKey, labelValue string) {
	if v, ok := np.Spec.PodSelector.MatchLabels[labelKey]; !ok || v != labelValue {
		g.Fail(fmt.Sprintf("NetworkPolicy %q podSelector: expected matchLabel %s=%s, got %v",
			np.Name, labelKey, labelValue, np.Spec.PodSelector.MatchLabels))
	}

	hasIngress, hasEgress := false, false
	for _, pt := range np.Spec.PolicyTypes {
		switch pt {
		case networkingv1.PolicyTypeIngress:
			hasIngress = true
		case networkingv1.PolicyTypeEgress:
			hasEgress = true
		}
	}
	if !hasIngress {
		g.Fail(fmt.Sprintf("NetworkPolicy %q: expected policyTypes to include Ingress", np.Name))
	}
	if !hasEgress {
		g.Fail(fmt.Sprintf("NetworkPolicy %q: expected policyTypes to include Egress", np.Name))
	}

	if !hasIngressPort(np, 8443) {
		g.Fail(fmt.Sprintf("NetworkPolicy %q: expected an ingress rule allowing TCP port 8443 for metrics scraping", np.Name))
	}
	if !hasEgressPort(np, 5353) {
		g.Fail(fmt.Sprintf("NetworkPolicy %q: expected an egress rule allowing port 5353 for DNS resolution", np.Name))
	}
}

func hasIngressPort(np *networkingv1.NetworkPolicy, port int) bool {
	for _, rule := range np.Spec.Ingress {
		for _, p := range rule.Ports {
			if p.Port != nil && int(p.Port.IntVal) == port {
				return true
			}
		}
	}
	return false
}

func hasEgressPort(np *networkingv1.NetworkPolicy, port int) bool {
	for _, rule := range np.Spec.Egress {
		for _, p := range rule.Ports {
			if p.Port != nil && int(p.Port.IntVal) == port {
				return true
			}
		}
	}
	return false
}

func existingNetworkPolicyNames(policies []networkingv1.NetworkPolicy) []string {
	names := make([]string, 0, len(policies))
	for _, np := range policies {
		names = append(names, np.Name)
	}
	return names
}
