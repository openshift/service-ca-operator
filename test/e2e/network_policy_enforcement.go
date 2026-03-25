package e2e

import (
	"context"
	"fmt"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.45"
)

var _ = g.Describe("[sig-service-ca] service-ca-operator", func() {
	g.It("[Operator][NetworkPolicy] should enforce NetworkPolicy allow/deny basics in a test namespace", func() {
		testGenericNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce service-ca-operator NetworkPolicies", func() {
		testServiceCAOperatorNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce cross-namespace ingress traffic", func() {
		testCrossNamespaceIngressEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should allow metrics but block other ports", func() {
		testMetricsOpenButOtherPortsBlocked()
	})
	g.It("[Operator][NetworkPolicy] should allow metrics ingress from any namespace", func() {
		testMetricsIngressOpenAccess()
	})
})

func testGenericNetworkPolicyEnforcement() {
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating a temporary namespace for policy enforcement checks")
	nsName := fmt.Sprintf("np-enforcement-%s", rand.String(5))
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
		},
	}
	_, err = kubeClient.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	defer func() {
		g.GinkgoWriter.Printf("deleting test namespace %s\n", nsName)
		_ = kubeClient.CoreV1().Namespaces().Delete(context.TODO(), nsName, metav1.DeleteOptions{})
	}()

	serverName := "np-server"
	clientLabels := map[string]string{"app": "np-client"}
	serverLabels := map[string]string{"app": "np-server"}

	g.GinkgoWriter.Printf("creating netexec server pod %s/%s\n", nsName, serverName)
	serverPod := netexecPod(serverName, nsName, serverLabels, 8080)
	_, err = kubeClient.CoreV1().Pods(nsName).Create(context.TODO(), serverPod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(waitForPodReady(kubeClient, nsName, serverName)).NotTo(o.HaveOccurred())

	server, err := kubeClient.CoreV1().Pods(nsName).Get(context.TODO(), serverName, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(server.Status.PodIP).NotTo(o.BeEmpty())
	g.GinkgoWriter.Printf("server pod %s/%s ip=%s\n", nsName, serverName, server.Status.PodIP)

	g.By("Verifying allow-all when no policies select the pod")
	g.GinkgoWriter.Printf("expecting allow from %s to %s:%d\n", nsName, server.Status.PodIP, 8080)
	expectConnectivity(kubeClient, nsName, clientLabels, server.Status.PodIP, 8080, true)

	g.By("Applying default deny and verifying traffic is blocked")
	g.GinkgoWriter.Printf("creating default-deny policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), defaultDenyPolicy("default-deny", nsName), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.GinkgoWriter.Printf("expecting deny from %s to %s:%d\n", nsName, server.Status.PodIP, 8080)
	expectConnectivity(kubeClient, nsName, clientLabels, server.Status.PodIP, 8080, false)

	g.By("Adding ingress allow only and verifying traffic is still blocked")
	g.GinkgoWriter.Printf("creating allow-ingress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), allowIngressPolicy("allow-ingress", nsName, serverLabels, clientLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.GinkgoWriter.Printf("expecting deny from %s to %s:%d (egress still blocked)\n", nsName, server.Status.PodIP, 8080)
	expectConnectivity(kubeClient, nsName, clientLabels, server.Status.PodIP, 8080, false)

	g.By("Adding egress allow and verifying traffic is permitted")
	g.GinkgoWriter.Printf("creating allow-egress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), allowEgressPolicy("allow-egress", nsName, clientLabels, serverLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.GinkgoWriter.Printf("expecting allow from %s to %s:%d\n", nsName, server.Status.PodIP, 8080)
	expectConnectivity(kubeClient, nsName, clientLabels, server.Status.PodIP, 8080, true)
}

func testServiceCAOperatorNetworkPolicyEnforcement() {
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-service-ca-operator"
	serverLabels := map[string]string{"app": "service-ca-operator"}

	g.By("Creating service-ca-operator test pod for policy checks")
	g.GinkgoWriter.Printf("creating service-ca-operator server pod in %s\n", namespace)
	serverIP, cleanupServer := createServerPod(kubeClient, namespace, "np-svc-ca-op-server", serverLabels, 8443)
	defer cleanupServer()

	g.By("Verifying cross-namespace traffic from monitoring is allowed")
	g.GinkgoWriter.Printf("expecting allow from openshift-monitoring to %s:%d\n", serverIP, 8443)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIP, 8443, true)

	g.By("Verifying unauthorized ports are denied")
	g.GinkgoWriter.Printf("expecting deny from openshift-monitoring to %s:%d (unauthorized port)\n", serverIP, 12345)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIP, 12345, false)

	g.By("Verifying within-namespace traffic to metrics port is allowed")
	g.GinkgoWriter.Printf("expecting allow from same namespace to %s:%d (metrics now open)\n", serverIP, 8443)
	expectConnectivity(kubeClient, namespace, map[string]string{"app": "service-ca-operator"}, serverIP, 8443, true)
}

func testCrossNamespaceIngressEnforcement() {
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in service-ca-operator namespace")
	svcCAOperatorIP, cleanupSvcCAOperator := createServerPod(kubeClient, "openshift-service-ca-operator", "np-svc-ca-op-xns", map[string]string{"app": "service-ca-operator"}, 8443)
	defer cleanupSvcCAOperator()

	g.By("Testing cross-namespace ingress: monitoring -> service-ca-operator:8443")
	g.GinkgoWriter.Printf("expecting allow from openshift-monitoring to %s:8443\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, svcCAOperatorIP, 8443, true)

	g.By("Testing cross-namespace ingress: any pod from monitoring can access metrics")
	g.GinkgoWriter.Printf("expecting allow from openshift-monitoring with any labels to %s:8443\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app": "any-label"}, svcCAOperatorIP, 8443, true)
}

func testMetricsOpenButOtherPortsBlocked() {
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pod in service-ca-operator namespace")
	svcCAOperatorIP, cleanupSvcCAOperator := createServerPod(kubeClient, "openshift-service-ca-operator", "np-svc-ca-op-unauth", map[string]string{"app": "service-ca-operator"}, 8443)
	defer cleanupSvcCAOperator()

	g.By("Testing metrics port 8443 is now open: default namespace -> service-ca-operator:8443")
	g.GinkgoWriter.Printf("expecting allow from default to %s:8443 (metrics now open to all)\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "default", map[string]string{"test": "client"}, svcCAOperatorIP, 8443, true)

	g.By("Testing metrics port 8443 is now open: openshift-etcd -> service-ca-operator:8443")
	g.GinkgoWriter.Printf("expecting allow from openshift-etcd to %s:8443 (metrics now open to all)\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "openshift-etcd", map[string]string{"test": "client"}, svcCAOperatorIP, 8443, true)

	g.By("Testing port-based blocking: unauthorized ports are still blocked")
	g.GinkgoWriter.Printf("expecting deny from openshift-monitoring to %s:9999 (unauthorized port)\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, svcCAOperatorIP, 9999, false)

	g.By("Testing multiple unauthorized ports are still blocked by default-deny")
	for _, port := range []int32{80, 443, 8080, 22, 3306, 9090} {
		g.GinkgoWriter.Printf("expecting deny from default to %s:%d (unauthorized port)\n", svcCAOperatorIP, port)
		expectConnectivity(kubeClient, "default", map[string]string{"test": "any-pod"}, svcCAOperatorIP, port, false)
	}
}

func testMetricsIngressOpenAccess() {
	kubeClient, _, err := getKubeClientAndConfig()
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pod in service-ca-operator namespace with operator labels")
	svcCAOperatorIP, cleanupSvcCAOperator := createServerPod(kubeClient, "openshift-service-ca-operator", "np-metrics-test", map[string]string{"app": "service-ca-operator"}, 8443)
	defer cleanupSvcCAOperator()

	g.By("Testing metrics policy: monitoring namespace can access metrics -> operator:8443")
	g.GinkgoWriter.Printf("expecting allow from openshift-monitoring to %s:8443\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, svcCAOperatorIP, 8443, true)

	g.By("Testing metrics policy: other system namespaces can access metrics -> operator:8443")
	g.GinkgoWriter.Printf("expecting allow from openshift-etcd to %s:8443\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "openshift-etcd", map[string]string{"test": "metrics-client"}, svcCAOperatorIP, 8443, true)

	g.By("Testing metrics policy: default namespace can access metrics -> operator:8443")
	g.GinkgoWriter.Printf("expecting allow from default namespace to %s:8443\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "default", map[string]string{"test": "client"}, svcCAOperatorIP, 8443, true)

	g.By("Testing metrics policy: same namespace can access metrics -> operator:8443")
	g.GinkgoWriter.Printf("expecting allow from openshift-service-ca-operator to %s:8443 (same namespace)\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "openshift-service-ca-operator", map[string]string{"app": "service-ca-operator"}, svcCAOperatorIP, 8443, true)

	g.By("Testing default-deny still blocks unauthorized ports")
	g.GinkgoWriter.Printf("expecting deny from openshift-monitoring to %s:9090 (wrong port, not allowed by any policy)\n", svcCAOperatorIP)
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, svcCAOperatorIP, 9090, false)
}

func netexecPod(name, namespace string, labels map[string]string, port int32) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   boolptr(true),
				RunAsUser:      int64ptr(1001),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{
				{
					Name:  "netexec",
					Image: agnhostImage,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolptr(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						RunAsNonRoot:             boolptr(true),
						RunAsUser:                int64ptr(1001),
					},
					Command: []string{"/agnhost"},
					Args:    []string{"netexec", fmt.Sprintf("--http-port=%d", port)},
					Ports: []corev1.ContainerPort{
						{ContainerPort: port},
					},
				},
			},
		},
	}
}

func createServerPod(kubeClient kubernetes.Interface, namespace, name string, labels map[string]string, port int32) (string, func()) {
	g.GinkgoHelper()

	g.GinkgoWriter.Printf("creating server pod %s/%s port=%d labels=%v\n", namespace, name, port, labels)
	pod := netexecPod(name, namespace, labels, port)
	_, err := kubeClient.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(waitForPodReady(kubeClient, namespace, name)).NotTo(o.HaveOccurred())

	created, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(created.Status.PodIP).NotTo(o.BeEmpty())
	g.GinkgoWriter.Printf("server pod %s/%s ip=%s\n", namespace, name, created.Status.PodIP)

	return created.Status.PodIP, func() {
		g.GinkgoWriter.Printf("deleting server pod %s/%s\n", namespace, name)
		_ = kubeClient.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	}
}

func defaultDenyPolicy(name, namespace string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
}

func allowIngressPolicy(name, namespace string, podLabels, fromLabels map[string]string, port int32) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabels},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: fromLabels}},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: port}, Protocol: protocolPtr(corev1.ProtocolTCP)},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
}

func allowEgressPolicy(name, namespace string, podLabels, toLabels map[string]string, port int32) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabels},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: toLabels}},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: port}, Protocol: protocolPtr(corev1.ProtocolTCP)},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
}

func expectConnectivity(kubeClient kubernetes.Interface, namespace string, clientLabels map[string]string, serverIP string, port int32, shouldSucceed bool) {
	g.GinkgoHelper()

	err := wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		succeeded, err := runConnectivityCheck(kubeClient, namespace, clientLabels, serverIP, port)
		if err != nil {
			return false, err
		}
		return succeeded == shouldSucceed, nil
	})
	o.Expect(err).NotTo(o.HaveOccurred())
	g.GinkgoWriter.Printf("connectivity %s/%s:%d expected=%t\n", namespace, serverIP, port, shouldSucceed)
}

func runConnectivityCheck(kubeClient kubernetes.Interface, namespace string, labels map[string]string, serverIP string, port int32) (bool, error) {
	g.GinkgoHelper()

	name := fmt.Sprintf("np-client-%s", rand.String(5))
	g.GinkgoWriter.Printf("creating client pod %s/%s to connect %s:%d\n", namespace, name, serverIP, port)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   boolptr(true),
				RunAsUser:      int64ptr(1001),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{
				{
					Name:  "connect",
					Image: agnhostImage,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolptr(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						RunAsNonRoot:             boolptr(true),
						RunAsUser:                int64ptr(1001),
					},
					Command: []string{"/agnhost"},
					Args: []string{
						"connect",
						"--protocol=tcp",
						"--timeout=5s",
						fmt.Sprintf("%s:%d", serverIP, port),
					},
				},
			},
		},
	}

	_, err := kubeClient.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	defer func() {
		_ = kubeClient.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	}()

	if err := waitForPodCompletion(kubeClient, namespace, name); err != nil {
		return false, err
	}
	completed, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if len(completed.Status.ContainerStatuses) == 0 {
		return false, fmt.Errorf("no container status recorded for pod %s", name)
	}
	exitCode := completed.Status.ContainerStatuses[0].State.Terminated.ExitCode
	g.GinkgoWriter.Printf("client pod %s/%s exitCode=%d\n", namespace, name, exitCode)
	return exitCode == 0, nil
}

func waitForPodReady(kubeClient kubernetes.Interface, namespace, name string) error {
	return wait.PollImmediate(2*time.Second, 2*time.Minute, func() (bool, error) {
		pod, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if pod.Status.Phase != corev1.PodRunning {
			return false, nil
		}
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
}

func waitForPodCompletion(kubeClient kubernetes.Interface, namespace, name string) error {
	return wait.PollImmediate(2*time.Second, 2*time.Minute, func() (bool, error) {
		pod, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed, nil
	})
}

func protocolPtr(protocol corev1.Protocol) *corev1.Protocol {
	return &protocol
}

func boolptr(value bool) *bool {
	return &value
}

func int64ptr(value int64) *int64 {
	return &value
}
