package operator

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/clock"
	kubediff "k8s.io/utils/diff"
	"sigs.k8s.io/yaml"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"

	"github.com/openshift/service-ca-operator/bindata"
)

func TestInitializeSigningSecret(t *testing.T) {
	testCases := map[string]struct {
		duration time.Duration
	}{
		"Zero duration should use default expiry": {
			duration: 0 * time.Hour,
		},
		"Negative duration should result in an expired cert": {
			duration: -2 * time.Hour,
		},
		"Positive duration should result in a short expiry": {
			duration: 2 * time.Hour,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			now := time.Now()
			secret := &corev1.Secret{}
			operator := &serviceCAOperator{}
			operator.initializeSigningSecret(secret, 0, tc.duration)

			// Check that the initialized key pair is valid
			rawCert := secret.Data[corev1.TLSCertKey]
			rawKey := secret.Data[corev1.TLSPrivateKeyKey]
			ca, err := crypto.GetCAFromBytes(rawCert, rawKey)
			if err != nil {
				t.Fatalf("Initialize signing secret failed to create a valid key pair: %v", err)
			}

			// Check that a non-zero duration affects the expiry

			expiry := ca.Config.Certs[0].NotAfter
			var minimumExpiry time.Time
			if tc.duration == 0*time.Nanosecond {
				minimumExpiry = now.Add(signingCertificateLifetime)
			} else {
				minimumExpiry = now.Add(tc.duration)
			}

			// Without overriding time.Now, need to account for the time taken between cert
			// generation and this check. If it's more than 30 seconds something is surely
			// broken.
			minimumExpiry = minimumExpiry.Add(-30 * time.Second)

			if !expiry.After(minimumExpiry) {
				t.Fatalf("Expected expiry of at least %v, got %v", minimumExpiry, expiry)
			}
		})
	}
}

func TestManageDeployment(t *testing.T) {
	baseDeployment := resourceread.ReadDeploymentV1OrDie(bindata.MustAsset("assets/deployment.yaml"))
	baseDeploymentPopulated := deployment(baseDeployment).withImage("foobar").withLogLevel(operatorv1.Normal).valueOrDie()
	tests := []struct {
		name                string
		runOnWorkers        bool
		loglevel            operatorv1.LogLevel
		image               string
		operatorVersion     string
		enabledFeatureGates map[string]bool
		expectedDeployment  *appsv1.Deployment
	}{
		{
			name:               "base deployment",
			runOnWorkers:       false,
			image:              "foobar",
			loglevel:           operatorv1.Normal,
			expectedDeployment: deployment(baseDeployment).withImage("foobar").withLogLevel(operatorv1.Normal).valueOrDie(),
		},
		{
			name:               "base deployment with higher debug level",
			runOnWorkers:       false,
			image:              "foobar",
			loglevel:           operatorv1.Debug,
			expectedDeployment: deployment(baseDeployment).withImage("foobar").withLogLevel(operatorv1.Debug).valueOrDie(),
		},
		{
			name:               "deploy on workers",
			runOnWorkers:       true,
			image:              "barbaz",
			loglevel:           operatorv1.Normal,
			expectedDeployment: deployment(baseDeployment).withImage("barbaz").withLogLevel(operatorv1.Normal).withNodeSelector(map[string]string{}).valueOrDie(),
		},
		{
			name:                "feature gates",
			image:               "foobar",
			runOnWorkers:        false,
			loglevel:            operatorv1.Normal,
			enabledFeatureGates: map[string]bool{"ShortCertRotation": true},
			expectedDeployment:  deployment(baseDeployment).withImage("foobar").withLogLevel(operatorv1.Normal).withFeatureGates([]string{"ShortCertRotation=true"}).valueOrDie(),
		},
		{
			name:               "operator version propagated to controller",
			image:              "foobar",
			loglevel:           operatorv1.Normal,
			operatorVersion:    "4.22.0",
			expectedDeployment: deployment(baseDeployment).withImage("foobar").withLogLevel(operatorv1.Normal).withOperatorVersionEnv("4.22.0").valueOrDie(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			appsClient := fake.NewSimpleClientset(baseDeploymentPopulated).AppsV1()
			os.Setenv("CONTROLLER_IMAGE", test.image)
			os.Setenv(operatorVersionEnvName, test.operatorVersion)
			operator := &serviceCAOperator{
				appsv1Client:        appsClient,
				eventRecorder:       events.NewInMemoryRecorder("managedeployment_test", clock.RealClock{}),
				enabledFeatureGates: test.enabledFeatureGates,
			}
			serviceCA := &operatorv1.ServiceCA{
				Spec: operatorv1.ServiceCASpec{
					OperatorSpec: operatorv1.OperatorSpec{
						LogLevel: test.loglevel,
					},
				},
			}
			resourcemerge.SetDeploymentGeneration(&serviceCA.Status.Generations, baseDeploymentPopulated)

			_, err := operator.manageDeployment(context.Background(), serviceCA, false, test.runOnWorkers)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			deployment, err := appsClient.Deployments(baseDeployment.Namespace).Get(context.Background(), baseDeployment.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equality.Semantic.DeepEqual(test.expectedDeployment, deployment) {
				t.Errorf("Expected deployment != actual: %v", kubediff.ObjectReflectDiff(test.expectedDeployment, deployment))
			}
		})
	}
}

type deploymentWrapper struct {
	Deployment *appsv1.Deployment
}

func deployment(base *appsv1.Deployment) *deploymentWrapper {
	return &deploymentWrapper{
		Deployment: base.DeepCopy(),
	}
}

func (w *deploymentWrapper) valueOrDie() *appsv1.Deployment {
	if err := resourceapply.SetSpecHashAnnotation(&w.Deployment.ObjectMeta, w.Deployment.Spec); err != nil {
		panic(err)
	}

	return w.Deployment
}

func (w *deploymentWrapper) withImage(image string) *deploymentWrapper {
	if w.Deployment.Annotations == nil {
		w.Deployment.Annotations = map[string]string{}
	}
	if len(w.Deployment.Spec.Template.Spec.Containers) > 0 {
		w.Deployment.Spec.Template.Spec.Containers[0].Image = image
	}
	return w
}

func (w *deploymentWrapper) withLogLevel(logLevel operatorv1.LogLevel) *deploymentWrapper {
	if len(w.Deployment.Spec.Template.Spec.Containers) > 0 {
		arg := fmt.Sprintf("-v=%d", loglevel.LogLevelToVerbosity(logLevel))
		w.Deployment.Spec.Template.Spec.Containers[0].Args = append(w.Deployment.Spec.Template.Spec.Containers[0].Args, arg)
	}
	return w
}

func (w *deploymentWrapper) withNodeSelector(selector map[string]string) *deploymentWrapper {
	w.Deployment.Spec.Template.Spec.NodeSelector = selector
	return w
}

func (w *deploymentWrapper) withFeatureGates(featureGates []string) *deploymentWrapper {
	if len(w.Deployment.Spec.Template.Spec.Containers) > 0 {
		arg := fmt.Sprintf("--feature-gates=%s", strings.Join(featureGates, ","))
		w.Deployment.Spec.Template.Spec.Containers[0].Args = append(w.Deployment.Spec.Template.Spec.Containers[0].Args, arg)
	}
	return w
}

func (w *deploymentWrapper) withOperatorVersionEnv(value string) *deploymentWrapper {
	if len(w.Deployment.Spec.Template.Spec.Containers) > 0 {
		for i := range w.Deployment.Spec.Template.Spec.Containers[0].Env {
			if w.Deployment.Spec.Template.Spec.Containers[0].Env[i].Name == operatorVersionEnvName {
				w.Deployment.Spec.Template.Spec.Containers[0].Env[i].Value = value
				return w
			}
		}
	}
	return w
}

func TestManageControllerConfig(t *testing.T) {
	tests := []struct {
		name                     string
		observedConfig           string
		expectedMinTLSVersion    string
		expectedCipherSuites     []string
		expectedCurvePreferences []int32
		expectedError            string
	}{
		{
			name:           "no observed config",
			observedConfig: "",
		},
		{
			name:                  "min tls version and cipher suites only",
			observedConfig:        `{"servingInfo":{"minTLSVersion":"VersionTLS12","cipherSuites":["TLS_AES_128_GCM_SHA256"]}}`,
			expectedMinTLSVersion: "VersionTLS12",
			expectedCipherSuites:  []string{"TLS_AES_128_GCM_SHA256"},
		},
		{
			name:                     "curve preferences are propagated",
			observedConfig:           `{"servingInfo":{"minTLSVersion":"VersionTLS12","curvePreferences":[4588,29,23,24]}}`,
			expectedMinTLSVersion:    "VersionTLS12",
			expectedCurvePreferences: []int32{4588, 29, 23, 24},
		},
		{
			name:           "empty curve preferences are ignored",
			observedConfig: `{"servingInfo":{"curvePreferences":[]}}`,
		},
		{
			name:           "non-integral curve preference is rejected",
			observedConfig: `{"servingInfo":{"curvePreferences":[29.5]}}`,
			expectedError:  "cannot unmarshal number 29.5 into Go struct field .servingInfo.curvePreferences of type int32",
		},
		{
			name:           "curve preference of the wrong type is rejected",
			observedConfig: `{"servingInfo":{"curvePreferences":["X25519"]}}`,
			expectedError:  "cannot unmarshal string into Go struct field .servingInfo.curvePreferences of type int32",
		},
		{
			name:           "out of int32 range curve preference is rejected",
			observedConfig: `{"servingInfo":{"curvePreferences":[4294967296]}}`,
			expectedError:  "cannot unmarshal number 4294967296 into Go struct field .servingInfo.curvePreferences of type int32",
		},
		{
			name:           "cipher suites of the wrong type are rejected",
			observedConfig: `{"servingInfo":{"cipherSuites":"TLS_AES_128_GCM_SHA256"}}`,
			expectedError:  "cannot unmarshal string into Go struct field .servingInfo.cipherSuites of type []string",
		},
		{
			name:                  "unknown observed fields are ignored",
			observedConfig:        `{"servingInfo":{"minTLSVersion":"VersionTLS12"},"somethingElse":{"a":1}}`,
			expectedMinTLSVersion: "VersionTLS12",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			operator := &serviceCAOperator{
				corev1Client:  client.CoreV1(),
				eventRecorder: events.NewInMemoryRecorder("managecontrollerconfig_test", clock.RealClock{}),
			}
			serviceCA := &operatorv1.ServiceCA{}
			if len(test.observedConfig) > 0 {
				serviceCA.Spec.ObservedConfig = runtime.RawExtension{Raw: []byte(test.observedConfig)}
			}

			_, err := operator.manageControllerConfig(context.Background(), serviceCA)
			if len(test.expectedError) > 0 {
				if err == nil {
					t.Fatalf("expected an error containing %q, got none", test.expectedError)
				}
				if !strings.Contains(err.Error(), test.expectedError) {
					t.Fatalf("expected an error containing %q, got %v", test.expectedError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expectedConfigMap := resourceread.ReadConfigMapV1OrDie(bindata.MustAsset("assets/controller-config.yaml"))
			configMap, err := client.CoreV1().ConfigMaps(expectedConfigMap.Namespace).Get(context.Background(), expectedConfigMap.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Parse as the type the controller process actually decodes the config into.
			config := &operatorv1alpha1.GenericOperatorConfig{}
			if err := yaml.Unmarshal([]byte(configMap.Data["controller-config.yaml"]), config); err != nil {
				t.Fatalf("failed to unmarshal the generated controller config: %v", err)
			}

			if config.ServingInfo.MinTLSVersion != test.expectedMinTLSVersion {
				t.Errorf("expected minTLSVersion %q, got %q", test.expectedMinTLSVersion, config.ServingInfo.MinTLSVersion)
			}
			if !equality.Semantic.DeepEqual(test.expectedCipherSuites, config.ServingInfo.CipherSuites) {
				t.Errorf("expected cipherSuites %v, got %v", test.expectedCipherSuites, config.ServingInfo.CipherSuites)
			}
			if !equality.Semantic.DeepEqual(test.expectedCurvePreferences, config.ServingInfo.CurvePreferences) {
				t.Errorf("expected curvePreferences %v, got %v", test.expectedCurvePreferences, config.ServingInfo.CurvePreferences)
			}
		})
	}
}
