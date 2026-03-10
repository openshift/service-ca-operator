package e2e

import (
	"context"
	"fmt"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	configclient "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
)

const (
	serviceCANamespace         = "openshift-service-ca"
	serviceCAOperatorNamespace = "openshift-service-ca-operator"
	defaultDenyPolicyName      = "default-deny-all"
	operandPolicyName          = "service-ca"
	operatorPolicyName         = "service-ca-operator"
)

var _ = g.Describe("[sig-service-ca] service-ca-operator", func() {
	g.It("[Operator][NetworkPolicy] should ensure service-ca NetworkPolicies are defined", func() {
		testServiceCANetworkPolicies()
	})
	g.It("[Operator][NetworkPolicy] should restore service-ca NetworkPolicies after delete or mutation[Timeout: 30m]", func() {
		testServiceCANetworkPolicyReconcile()
	})
})

func testServiceCANetworkPolicies() {
	ctx := context.Background()
	g.By("Creating Kubernetes clients")
	kubeClient, config, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())
	configClient, err := configclient.NewForConfig(config)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for service-ca ClusterOperator to be stable")
	err = waitForClusterOperatorAvailableNotProgressingNotDegraded(configClient, "service-ca")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Validating NetworkPolicies in openshift-service-ca")
	operandDefaultDeny := getNetworkPolicy(ctx, kubeClient, serviceCANamespace, defaultDenyPolicyName)
	logNetworkPolicySummary("service-ca/default-deny-all", operandDefaultDeny)
	logNetworkPolicyDetails("service-ca/default-deny-all", operandDefaultDeny)
	requireDefaultDenyAll(operandDefaultDeny)

	operandPolicy := getNetworkPolicy(ctx, kubeClient, serviceCANamespace, operandPolicyName)
	logNetworkPolicySummary("service-ca/service-ca", operandPolicy)
	logNetworkPolicyDetails("service-ca/service-ca", operandPolicy)
	requirePodSelectorLabel(operandPolicy, "app", "service-ca")
	requireIngressPort(operandPolicy, corev1.ProtocolTCP, 8443)
	requireEgressPort(operandPolicy, corev1.ProtocolTCP, 5353)
	requireEgressPort(operandPolicy, corev1.ProtocolUDP, 5353)
	requireEgressToNamespace(operandPolicy, "openshift-dns")
	requireEgressAllowAll(operandPolicy)

	g.By("Validating NetworkPolicies in openshift-service-ca-operator")
	operatorDefaultDeny := getNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, defaultDenyPolicyName)
	logNetworkPolicySummary("service-ca-operator/default-deny-all", operatorDefaultDeny)
	logNetworkPolicyDetails("service-ca-operator/default-deny-all", operatorDefaultDeny)
	requireDefaultDenyAll(operatorDefaultDeny)

	operatorPolicy := getNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, operatorPolicyName)
	logNetworkPolicySummary("service-ca-operator/service-ca-operator", operatorPolicy)
	logNetworkPolicyDetails("service-ca-operator/service-ca-operator", operatorPolicy)
	requirePodSelectorLabel(operatorPolicy, "app", "service-ca-operator")
	requireIngressPort(operatorPolicy, corev1.ProtocolTCP, 8443)
	requireEgressPort(operatorPolicy, corev1.ProtocolTCP, 5353)
	requireEgressPort(operatorPolicy, corev1.ProtocolUDP, 5353)
	requireEgressToNamespace(operatorPolicy, "openshift-dns")
	requireEgressAllowAll(operatorPolicy)

	g.By("Verifying pods are ready in service-ca namespaces")
	waitForPodsReadyByLabel(ctx, kubeClient, serviceCAOperatorNamespace, "app=service-ca-operator")
}

func testServiceCANetworkPolicyReconcile() {
	ctx := context.Background()
	g.By("Creating Kubernetes clients")
	kubeClient, config, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())
	configClient, err := configclient.NewForConfig(config)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for service-ca ClusterOperator to be stable")
	err = waitForClusterOperatorAvailableNotProgressingNotDegraded(configClient, "service-ca")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Deleting operator policies and waiting for restoration")
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", serviceCAOperatorNamespace, operatorPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, operatorPolicyName)

	g.By("Deleting operand policies and waiting for restoration")
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", serviceCANamespace, operandPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, serviceCANamespace, operandPolicyName)

	g.By("Deleting default-deny policies and waiting for restoration")
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", serviceCAOperatorNamespace, defaultDenyPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, defaultDenyPolicyName)
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", serviceCANamespace, defaultDenyPolicyName)
	restoreNetworkPolicy(ctx, kubeClient, serviceCANamespace, defaultDenyPolicyName)

	g.By("Mutating operator policies and waiting for reconciliation")
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", serviceCAOperatorNamespace, operatorPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, operatorPolicyName)

	g.By("Mutating operand policies and waiting for reconciliation")
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", serviceCANamespace, operandPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, serviceCANamespace, operandPolicyName)

	g.By("Mutating default-deny policies and waiting for reconciliation")
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", serviceCAOperatorNamespace, defaultDenyPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, defaultDenyPolicyName)
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s\n", serviceCANamespace, defaultDenyPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, serviceCANamespace, defaultDenyPolicyName)

	g.By("Checking NetworkPolicy-related events (best-effort)")
	logNetworkPolicyEvents(ctx, kubeClient, []string{serviceCAOperatorNamespace, serviceCANamespace}, operatorPolicyName)
}

func getNetworkPolicy(ctx context.Context, client kubernetes.Interface, namespace, name string) *networkingv1.NetworkPolicy {
	g.GinkgoHelper()
	policy, err := client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get NetworkPolicy %s/%s", namespace, name)
	return policy
}

func requireDefaultDenyAll(policy *networkingv1.NetworkPolicy) {
	g.GinkgoHelper()
	if len(policy.Spec.PodSelector.MatchLabels) != 0 || len(policy.Spec.PodSelector.MatchExpressions) != 0 {
		g.Fail(fmt.Sprintf("%s/%s: expected empty podSelector", policy.Namespace, policy.Name))
	}

	policyTypes := sets.NewString()
	for _, policyType := range policy.Spec.PolicyTypes {
		policyTypes.Insert(string(policyType))
	}
	if !policyTypes.Has(string(networkingv1.PolicyTypeIngress)) || !policyTypes.Has(string(networkingv1.PolicyTypeEgress)) {
		g.Fail(fmt.Sprintf("%s/%s: expected both Ingress and Egress policyTypes, got %v", policy.Namespace, policy.Name, policy.Spec.PolicyTypes))
	}
}

func requirePodSelectorLabel(policy *networkingv1.NetworkPolicy, key, value string) {
	g.GinkgoHelper()
	actual, ok := policy.Spec.PodSelector.MatchLabels[key]
	if !ok || actual != value {
		g.Fail(fmt.Sprintf("%s/%s: expected podSelector %s=%s, got %v", policy.Namespace, policy.Name, key, value, policy.Spec.PodSelector.MatchLabels))
	}
}

func requireIngressPort(policy *networkingv1.NetworkPolicy, protocol corev1.Protocol, port int32) {
	g.GinkgoHelper()
	if !hasPortInIngress(policy.Spec.Ingress, protocol, port) {
		g.Fail(fmt.Sprintf("%s/%s: expected ingress port %s/%d", policy.Namespace, policy.Name, protocol, port))
	}
}

func requireEgressPort(policy *networkingv1.NetworkPolicy, protocol corev1.Protocol, port int32) {
	g.GinkgoHelper()
	if !hasPortInEgress(policy.Spec.Egress, protocol, port) {
		g.Fail(fmt.Sprintf("%s/%s: expected egress port %s/%d", policy.Namespace, policy.Name, protocol, port))
	}
}

func requireEgressToNamespace(policy *networkingv1.NetworkPolicy, namespace string) {
	g.GinkgoHelper()
	if !hasEgressToNamespace(policy.Spec.Egress, namespace) {
		g.Fail(fmt.Sprintf("%s/%s: expected egress to namespace %s", policy.Namespace, policy.Name, namespace))
	}
}

func requireEgressAllowAll(policy *networkingv1.NetworkPolicy) {
	g.GinkgoHelper()
	if !hasEgressAllowAll(policy.Spec.Egress) {
		g.Fail(fmt.Sprintf("%s/%s: expected egress allow-all", policy.Namespace, policy.Name))
	}
}

func hasPortInIngress(rules []networkingv1.NetworkPolicyIngressRule, protocol corev1.Protocol, port int32) bool {
	for _, rule := range rules {
		if hasPort(rule.Ports, protocol, port) {
			return true
		}
	}
	return false
}

func hasPortInEgress(rules []networkingv1.NetworkPolicyEgressRule, protocol corev1.Protocol, port int32) bool {
	for _, rule := range rules {
		if hasPort(rule.Ports, protocol, port) {
			return true
		}
	}
	return false
}

func hasPort(ports []networkingv1.NetworkPolicyPort, protocol corev1.Protocol, port int32) bool {
	for _, p := range ports {
		if p.Port == nil || p.Port.IntValue() != int(port) {
			continue
		}
		if p.Protocol == nil || *p.Protocol == protocol {
			return true
		}
	}
	return false
}

func hasEgressToNamespace(rules []networkingv1.NetworkPolicyEgressRule, namespace string) bool {
	for _, rule := range rules {
		for _, peer := range rule.To {
			if namespaceSelectorMatches(peer.NamespaceSelector, namespace) {
				return true
			}
		}
	}
	return false
}

func hasEgressAllowAll(rules []networkingv1.NetworkPolicyEgressRule) bool {
	for _, rule := range rules {
		if len(rule.To) == 0 && len(rule.Ports) == 0 {
			return true
		}
	}
	return false
}

func namespaceSelectorMatches(selector *metav1.LabelSelector, namespace string) bool {
	if selector == nil {
		return false
	}
	if selector.MatchLabels != nil {
		if selector.MatchLabels["kubernetes.io/metadata.name"] == namespace {
			return true
		}
	}
	for _, expr := range selector.MatchExpressions {
		if expr.Key != "kubernetes.io/metadata.name" {
			continue
		}
		if expr.Operator != metav1.LabelSelectorOpIn {
			continue
		}
		for _, value := range expr.Values {
			if value == namespace {
				return true
			}
		}
	}
	return false
}

func restoreNetworkPolicy(ctx context.Context, client kubernetes.Interface, namespace, name string) {
	g.GinkgoHelper()
	g.GinkgoWriter.Printf("deleting NetworkPolicy %s/%s\n", namespace, name)
	o.Expect(client.NetworkingV1().NetworkPolicies(namespace).Delete(ctx, name, metav1.DeleteOptions{})).NotTo(o.HaveOccurred())
	err := wait.PollImmediate(5*time.Second, 10*time.Minute, func() (bool, error) {
		_, err := client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "timed out waiting for NetworkPolicy %s/%s to be restored", namespace, name)
	g.GinkgoWriter.Printf("NetworkPolicy %s/%s restored\n", namespace, name)
}

func mutateAndRestoreNetworkPolicy(ctx context.Context, client kubernetes.Interface, namespace, name string) {
	g.GinkgoHelper()
	original := getNetworkPolicy(ctx, client, namespace, name)
	g.GinkgoWriter.Printf("mutating NetworkPolicy %s/%s (podSelector override)\n", namespace, name)
	patch := []byte(`{"spec":{"podSelector":{"matchLabels":{"np-reconcile":"mutated"}}}}`)
	_, err := client.NetworkingV1().NetworkPolicies(namespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	err = wait.PollImmediate(5*time.Second, 10*time.Minute, func() (bool, error) {
		current := getNetworkPolicy(ctx, client, namespace, name)
		return equality.Semantic.DeepEqual(original.Spec, current.Spec), nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "timed out waiting for NetworkPolicy %s/%s spec to be restored", namespace, name)
	g.GinkgoWriter.Printf("NetworkPolicy %s/%s spec restored\n", namespace, name)
}

func waitForPodsReadyByLabel(ctx context.Context, client kubernetes.Interface, namespace, labelSelector string) {
	g.GinkgoHelper()
	g.GinkgoWriter.Printf("waiting for pods ready in %s with selector %s\n", namespace, labelSelector)
	err := wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil {
			return false, err
		}
		if len(pods.Items) == 0 {
			return false, nil
		}
		for _, pod := range pods.Items {
			if !isPodReady(&pod) {
				return false, nil
			}
		}
		return true, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "timed out waiting for pods in %s with selector %s to be ready", namespace, labelSelector)
}

func isPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func logNetworkPolicyEvents(ctx context.Context, client kubernetes.Interface, namespaces []string, policyName string) {
	g.GinkgoHelper()
	found := false
	_ = wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		for _, namespace := range namespaces {
			events, err := client.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				g.GinkgoWriter.Printf("unable to list events in %s: %v\n", namespace, err)
				continue
			}
			for _, event := range events.Items {
				if event.InvolvedObject.Kind == "NetworkPolicy" && event.InvolvedObject.Name == policyName {
					g.GinkgoWriter.Printf("event in %s: %s %s %s\n", namespace, event.Type, event.Reason, event.Message)
					found = true
				}
				if event.Message != "" && (event.InvolvedObject.Name == policyName || event.InvolvedObject.Kind == "NetworkPolicy") {
					g.GinkgoWriter.Printf("event in %s: %s %s %s\n", namespace, event.Type, event.Reason, event.Message)
					found = true
				}
			}
		}
		if found {
			return true, nil
		}
		g.GinkgoWriter.Printf("no NetworkPolicy events yet for %s (namespaces: %v)\n", policyName, namespaces)
		return false, nil
	})
	if !found {
		g.GinkgoWriter.Printf("no NetworkPolicy events observed for %s (best-effort)\n", policyName)
	}
}

func logNetworkPolicySummary(label string, policy *networkingv1.NetworkPolicy) {
	g.GinkgoWriter.Printf("networkpolicy %s namespace=%s name=%s podSelector=%v policyTypes=%v ingress=%d egress=%d\n",
		label,
		policy.Namespace,
		policy.Name,
		policy.Spec.PodSelector.MatchLabels,
		policy.Spec.PolicyTypes,
		len(policy.Spec.Ingress),
		len(policy.Spec.Egress),
	)
}

func logNetworkPolicyDetails(label string, policy *networkingv1.NetworkPolicy) {
	g.GinkgoHelper()
	g.GinkgoWriter.Printf("networkpolicy %s details:\n", label)
	g.GinkgoWriter.Printf("  podSelector=%v policyTypes=%v\n", policy.Spec.PodSelector.MatchLabels, policy.Spec.PolicyTypes)
	for i, rule := range policy.Spec.Ingress {
		g.GinkgoWriter.Printf("  ingress[%d]: ports=%s from=%s\n", i, formatPorts(rule.Ports), formatPeers(rule.From))
	}
	for i, rule := range policy.Spec.Egress {
		g.GinkgoWriter.Printf("  egress[%d]: ports=%s to=%s\n", i, formatPorts(rule.Ports), formatPeers(rule.To))
	}
}

func formatPorts(ports []networkingv1.NetworkPolicyPort) string {
	if len(ports) == 0 {
		return "[]"
	}
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		proto := "TCP"
		if p.Protocol != nil {
			proto = string(*p.Protocol)
		}
		if p.Port == nil {
			out = append(out, fmt.Sprintf("%s:any", proto))
			continue
		}
		out = append(out, fmt.Sprintf("%s:%s", proto, p.Port.String()))
	}
	return fmt.Sprintf("[%s]", joinStrings(out))
}

func formatPeers(peers []networkingv1.NetworkPolicyPeer) string {
	if len(peers) == 0 {
		return "[]"
	}
	out := make([]string, 0, len(peers))
	for _, peer := range peers {
		ns := formatSelector(peer.NamespaceSelector)
		pod := formatSelector(peer.PodSelector)
		if ns == "" && pod == "" {
			out = append(out, "{}")
			continue
		}
		out = append(out, fmt.Sprintf("ns=%s pod=%s", ns, pod))
	}
	return fmt.Sprintf("[%s]", joinStrings(out))
}

func formatSelector(sel *metav1.LabelSelector) string {
	if sel == nil {
		return ""
	}
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return "{}"
	}
	return fmt.Sprintf("labels=%v exprs=%v", sel.MatchLabels, sel.MatchExpressions)
}

func joinStrings(items []string) string {
	if len(items) == 0 {
		return ""
	}
	out := items[0]
	for i := 1; i < len(items); i++ {
		out += ", " + items[i]
	}
	return out
}

func waitForClusterOperatorAvailableNotProgressingNotDegraded(client configclient.ConfigV1Interface, name string) error {
	return wait.PollImmediate(5*time.Second, 10*time.Minute, func() (bool, error) {
		co, err := client.ClusterOperators().Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, condition := range co.Status.Conditions {
			switch condition.Type {
			case "Available":
				if condition.Status != "True" {
					g.GinkgoWriter.Printf("ClusterOperator %s is not Available: %s\n", name, condition.Message)
					return false, nil
				}
			case "Progressing":
				if condition.Status != "False" {
					g.GinkgoWriter.Printf("ClusterOperator %s is Progressing: %s\n", name, condition.Message)
					return false, nil
				}
			case "Degraded":
				if condition.Status != "False" {
					g.GinkgoWriter.Printf("ClusterOperator %s is Degraded: %s\n", name, condition.Message)
					return false, nil
				}
			}
		}
		return true, nil
	})
}
