package e2e

import (
	"context"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"

	configclient "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
)

const (
	serviceCANamespace         = operatorclient.TargetNamespace
	serviceCAOperatorNamespace = operatorclient.OperatorNamespace
	defaultDenyPolicyName      = "default-deny-all"
	operandPolicyName          = "service-ca"
	operatorPolicyName         = "service-ca-operator"
)

var _ = g.Describe("[sig-service-ca] service-ca-operator", func() {
	g.It("[Operator][NetworkPolicy] should ensure service-ca and service-ca-operator NetworkPolicies are defined", func() {
		testServiceCANetworkPolicies()
	})
	g.It("[Serial][Operator][NetworkPolicy] should restore service-ca NetworkPolicies after delete or mutation[Timeout:30m]", func() {
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
	err = waitForClusterOperatorAvailableNotProgressingNotDegraded(ctx, configClient, "service-ca")
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
	logIngressFromNamespaceOptional(operandPolicy, 8443, "openshift-monitoring")
	requireEgressPort(operandPolicy, corev1.ProtocolTCP, 5353)
	requireEgressPort(operandPolicy, corev1.ProtocolUDP, 5353)
	requireEgressToNamespace(operandPolicy, "openshift-dns")
	logEgressAllowAllTCP(operandPolicy)
	logIngressHostNetworkOrAllowAll(operandPolicy, 8443)

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
	logIngressFromNamespaceOptional(operatorPolicy, 8443, "openshift-monitoring")
	requireEgressPort(operatorPolicy, corev1.ProtocolTCP, 5353)
	requireEgressPort(operatorPolicy, corev1.ProtocolUDP, 5353)
	requireEgressToNamespace(operatorPolicy, "openshift-dns")
	logEgressAllowAllTCP(operatorPolicy)
	logIngressHostNetworkOrAllowAll(operatorPolicy, 8443)

	g.By("Verifying pods are ready in service-ca namespaces")
	waitForPodsReadyByLabel(ctx, kubeClient, serviceCAOperatorNamespace, "app=service-ca-operator")
	waitForPodsReadyByLabel(ctx, kubeClient, serviceCANamespace, "app=service-ca")
}

func testServiceCANetworkPolicyReconcile() {
	ctx := context.Background()
	g.By("Creating Kubernetes clients")
	kubeClient, config, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())
	configClient, err := configclient.NewForConfig(config)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for service-ca ClusterOperator to be stable")
	err = waitForClusterOperatorAvailableNotProgressingNotDegraded(ctx, configClient, "service-ca")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Capturing expected NetworkPolicy specs")
	expectedOperatorPolicy := getNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, operatorPolicyName)
	expectedOperandPolicy := getNetworkPolicy(ctx, kubeClient, serviceCANamespace, operandPolicyName)
	expectedOperatorDefaultDeny := getNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, defaultDenyPolicyName)
	expectedOperandDefaultDeny := getNetworkPolicy(ctx, kubeClient, serviceCANamespace, defaultDenyPolicyName)

	g.By("Deleting main policies and waiting for restoration")
	restoreNetworkPolicy(ctx, kubeClient, expectedOperatorPolicy)
	restoreNetworkPolicy(ctx, kubeClient, expectedOperandPolicy)

	g.By("Deleting default-deny-all policies and waiting for restoration")
	restoreNetworkPolicy(ctx, kubeClient, expectedOperatorDefaultDeny)
	restoreNetworkPolicy(ctx, kubeClient, expectedOperandDefaultDeny)

	g.By("Mutating main policies and waiting for reconciliation")
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, operatorPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, serviceCANamespace, operandPolicyName)

	g.By("Mutating default-deny-all policies and waiting for reconciliation")
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, serviceCAOperatorNamespace, defaultDenyPolicyName)
	mutateAndRestoreNetworkPolicy(ctx, kubeClient, serviceCANamespace, defaultDenyPolicyName)

	g.By("Checking NetworkPolicy-related events (best-effort)")
	logNetworkPolicyEvents(ctx, kubeClient, []string{serviceCAOperatorNamespace, serviceCANamespace}, operatorPolicyName)
}
