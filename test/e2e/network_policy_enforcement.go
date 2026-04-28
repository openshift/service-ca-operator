package e2e

import (
	"context"
	"fmt"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
)

var _ = g.Describe("[sig-service-ca] service-ca-operator", func() {
	g.It("[Operator][NetworkPolicy] should enforce NetworkPolicy allow/deny basics in a test namespace", func() {
		testGenericNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce service-ca-operator NetworkPolicies", func() {
		testServiceCAOperatorNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce service-ca NetworkPolicies", func() {
		testServiceCANetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce cross-namespace ingress traffic", func() {
		testCrossNamespaceIngressEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should block unauthorized namespace traffic", func() {
		testUnauthorizedNamespaceBlocking()
	})
})

func testGenericNetworkPolicyEnforcement() {
	ctx := context.Background()
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating a temporary namespace for policy enforcement checks")
	nsName := fmt.Sprintf("np-enforcement-%s", rand.String(5))
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
		},
	}
	_, err = kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.DeferCleanup(func() {
		g.GinkgoWriter.Printf("deleting test namespace %s\n", nsName)
		_ = kubeClient.CoreV1().Namespaces().Delete(ctx, nsName, metav1.DeleteOptions{})
	})

	serverName := "np-server"
	clientLabels := map[string]string{"app": "np-client"}
	serverLabels := map[string]string{"app": "np-server"}

	g.GinkgoWriter.Printf("creating netexec server pod %s/%s\n", nsName, serverName)
	serverPod := netexecPod(serverName, nsName, serverLabels, 8080)
	_, err = kubeClient.CoreV1().Pods(nsName).Create(ctx, serverPod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(waitForPodReady(ctx, kubeClient, nsName, serverName)).NotTo(o.HaveOccurred())

	server, err := kubeClient.CoreV1().Pods(nsName).Get(ctx, serverName, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(server.Status.PodIPs).NotTo(o.BeEmpty())
	serverIPs := podIPs(server)
	g.GinkgoWriter.Printf("server pod %s/%s ips=%v\n", nsName, serverName, serverIPs)

	g.By("Verifying allow-all when no policies select the pod")
	expectConnectivity(ctx, kubeClient, nsName, clientLabels, serverIPs, 8080, true)

	g.By("Applying default deny and verifying traffic is blocked")
	g.GinkgoWriter.Printf("creating default-deny policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(ctx, defaultDenyPolicy("default-deny", nsName), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Adding ingress allow only and verifying traffic is still blocked")
	g.GinkgoWriter.Printf("creating allow-ingress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(ctx, allowIngressPolicy("allow-ingress", nsName, serverLabels, clientLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	expectConnectivity(ctx, kubeClient, nsName, clientLabels, serverIPs, 8080, false)

	g.By("Adding egress allow and verifying traffic is permitted")
	g.GinkgoWriter.Printf("creating allow-egress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(ctx, allowEgressPolicy("allow-egress", nsName, clientLabels, serverLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	expectConnectivity(ctx, kubeClient, nsName, clientLabels, serverIPs, 8080, true)
}

func testServiceCAOperatorNetworkPolicyEnforcement() {
	ctx := context.Background()
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-service-ca-operator"
	serverLabels := map[string]string{"app": "service-ca-operator"}
	policy, err := kubeClient.NetworkingV1().NetworkPolicies(namespace).Get(ctx, "service-ca-operator", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating service-ca-operator test pods for policy checks")
	g.GinkgoWriter.Printf("creating service-ca-operator server pod in %s\n", namespace)
	serverIPs, cleanupServer := createServerPod(ctx, kubeClient, namespace, fmt.Sprintf("np-svc-ca-op-server-%s", rand.String(5)), serverLabels, 8443)
	g.DeferCleanup(cleanupServer)

	allowedFromSameNamespace := ingressAllowsFromNamespace(policy, namespace, serverLabels, 8443)
	g.By("Verifying within-namespace traffic matches policy")
	expectConnectivity(ctx, kubeClient, namespace, serverLabels, serverIPs, 8443, allowedFromSameNamespace)

	g.By("Verifying cross-namespace traffic from monitoring is allowed")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 8443, true)

	g.By("Verifying unauthorized ports are denied")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 12345, false)
}

func testServiceCANetworkPolicyEnforcement() {
	ctx := context.Background()
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-service-ca"
	serverLabels := map[string]string{"app": "service-ca"}
	policy, err := kubeClient.NetworkingV1().NetworkPolicies(namespace).Get(ctx, "service-ca", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating service-ca test pods for policy checks")
	g.GinkgoWriter.Printf("creating service-ca server pod in %s\n", namespace)
	serverIPs, cleanupServer := createServerPod(ctx, kubeClient, namespace, fmt.Sprintf("np-svc-ca-server-%s", rand.String(5)), serverLabels, 8443)
	g.DeferCleanup(cleanupServer)

	allowedFromSameNamespace := ingressAllowsFromNamespace(policy, namespace, serverLabels, 8443)
	g.By("Verifying within-namespace traffic matches policy")
	expectConnectivity(ctx, kubeClient, namespace, serverLabels, serverIPs, 8443, allowedFromSameNamespace)

	g.By("Verifying cross-namespace traffic from monitoring is allowed")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 8443, true)

	g.By("Verifying unauthorized ports are denied")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 12345, false)
}

func testCrossNamespaceIngressEnforcement() {
	ctx := context.Background()
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in service-ca namespaces")
	svcCAOperatorIPs, cleanupSvcCAOperator := createServerPod(ctx, kubeClient, "openshift-service-ca-operator", fmt.Sprintf("np-svc-ca-op-xns-%s", rand.String(5)), map[string]string{"app": "service-ca-operator"}, 8443)
	g.DeferCleanup(cleanupSvcCAOperator)

	svcCAIPs, cleanupSvcCA := createServerPod(ctx, kubeClient, "openshift-service-ca", fmt.Sprintf("np-svc-ca-xns-%s", rand.String(5)), map[string]string{"app": "service-ca"}, 8443)
	g.DeferCleanup(cleanupSvcCA)

	g.By("Testing cross-namespace ingress: monitoring -> service-ca-operator:8443")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, svcCAOperatorIPs, 8443, true)

	g.By("Testing cross-namespace ingress: monitoring -> service-ca:8443")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, svcCAIPs, 8443, true)

	g.By("Testing allow-all ingress: arbitrary namespace -> service-ca-operator:8443")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "arbitrary-client"}, svcCAOperatorIPs, 8443, true)

	g.By("Testing allow-all ingress: arbitrary namespace -> service-ca:8443")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "arbitrary-client"}, svcCAIPs, 8443, true)

	g.By("Testing denied cross-namespace: unauthorized namespace -> service-ca-operator on unauthorized port")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "arbitrary-client"}, svcCAOperatorIPs, 8080, false)

	g.By("Testing denied cross-namespace: unauthorized namespace -> service-ca on unauthorized port")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "arbitrary-client"}, svcCAIPs, 8080, false)
}

func testUnauthorizedNamespaceBlocking() {
	ctx := context.Background()
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in service-ca namespaces")
	svcCAOperatorIPs, cleanupSvcCAOperator := createServerPod(ctx, kubeClient, "openshift-service-ca-operator", fmt.Sprintf("np-svc-ca-op-unauth-%s", rand.String(5)), map[string]string{"app": "service-ca-operator"}, 8443)
	g.DeferCleanup(cleanupSvcCAOperator)
	svcCAOperatorPolicy, err := kubeClient.NetworkingV1().NetworkPolicies("openshift-service-ca-operator").Get(ctx, "service-ca-operator", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	svcCAIPs, cleanupSvcCA := createServerPod(ctx, kubeClient, "openshift-service-ca", fmt.Sprintf("np-svc-ca-unauth-%s", rand.String(5)), map[string]string{"app": "service-ca"}, 8443)
	g.DeferCleanup(cleanupSvcCA)
	svcCAPolicy, err := kubeClient.NetworkingV1().NetworkPolicies("openshift-service-ca").Get(ctx, "service-ca", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Testing allow-all rules: service-ca-operator:8443 (metrics endpoint)")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, svcCAOperatorIPs, 8443, true)

	g.By("Testing allow-all rules: service-ca:8443 (metrics endpoint)")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, svcCAIPs, 8443, true)

	g.By("Testing strict blocking: unauthorized namespace -> service-ca-operator on wrong port")
	defaultAllowed := ingressAllowsFromNamespace(svcCAOperatorPolicy, "default", map[string]string{"test": "unauthorized"}, 9999)
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "unauthorized"}, svcCAOperatorIPs, 9999, defaultAllowed)

	g.By("Testing strict blocking: unauthorized namespace -> service-ca on wrong port")
	defaultAllowedSvcCA := ingressAllowsFromNamespace(svcCAPolicy, "default", map[string]string{"test": "unauthorized"}, 9999)
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "unauthorized"}, svcCAIPs, 9999, defaultAllowedSvcCA)

	g.By("Testing strict blocking: unauthorized pod in openshift-etcd -> service-ca-operator:8443")
	// service-ca-operator ingress allows from any namespace on port 8443, but openshift-etcd has
	// its own default-deny + allow-all-egress policy that only permits egress for pods
	// with app in (guard, installer, pruner, cluster-backup-cronjob).
	// A pod with {"test": "unauthorized"} labels is blocked by etcd's egress policy.
	expectConnectivity(ctx, kubeClient, "openshift-etcd", map[string]string{"test": "unauthorized"}, svcCAOperatorIPs, 8443, false)

	g.By("Testing strict blocking: unauthorized pod in openshift-etcd -> service-ca:8443")
	expectConnectivity(ctx, kubeClient, "openshift-etcd", map[string]string{"test": "unauthorized"}, svcCAIPs, 8443, false)

	g.By("Testing port-based blocking: unauthorized port even from any namespace (service-ca-operator)")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, svcCAOperatorIPs, 9999, false)

	g.By("Testing port-based blocking: unauthorized port even from any namespace (service-ca)")
	expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, svcCAIPs, 9999, false)

	g.By("Testing allow-all ingress: wrong labels from allowed namespace (service-ca-operator)")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app": "wrong-label"}, svcCAOperatorIPs, 8443, true)

	g.By("Testing allow-all ingress: wrong labels from allowed namespace (service-ca)")
	expectConnectivity(ctx, kubeClient, "openshift-monitoring", map[string]string{"app": "wrong-label"}, svcCAIPs, 8443, true)

	g.By("Testing egress blocking: wrong labels in openshift-service-ca-operator (default-deny blocks egress)")
	expectConnectivity(ctx, kubeClient, "openshift-service-ca-operator", map[string]string{"app": "wrong-label"}, svcCAIPs, 8443, false)

	g.By("Testing egress blocking: wrong labels in openshift-service-ca (default-deny blocks egress)")
	expectConnectivity(ctx, kubeClient, "openshift-service-ca", map[string]string{"app": "wrong-label"}, svcCAOperatorIPs, 8443, false)

	g.By("Testing multiple unauthorized ports on service-ca-operator")
	for _, port := range []int32{80, 443, 8080, 22, 3306} {
		expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, svcCAOperatorIPs, port, false)
	}

	g.By("Testing multiple unauthorized ports on service-ca")
	for _, port := range []int32{80, 443, 8080, 22, 3306} {
		expectConnectivity(ctx, kubeClient, "default", map[string]string{"test": "any-pod"}, svcCAIPs, port, false)
	}
}
