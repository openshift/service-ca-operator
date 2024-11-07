package operator

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	kubediff "k8s.io/utils/diff"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"

	"github.com/openshift/service-ca-operator/pkg/operator/v4_00_assets"
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
			initializeSigningSecret(secret, 0)

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
	baseDeployment := resourceread.ReadDeploymentV1OrDie(v4_00_assets.MustAsset(resourcePath + "deployment.yaml"))
	baseDeploymentPopulated := deployment(baseDeployment).withImage("foobar").withLogLevel(operatorv1.Normal).valueOrDie()
	tests := []struct {
		name               string
		runOnWorkers       bool
		loglevel           operatorv1.LogLevel
		image              string
		expectedDeployment *appsv1.Deployment
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			appsClient := fake.NewSimpleClientset(baseDeploymentPopulated).AppsV1()
			os.Setenv("CONTROLLER_IMAGE", test.image)
			operator := &serviceCAOperator{
				appsv1Client:  appsClient,
				eventRecorder: events.NewInMemoryRecorder("managedeployment_test"),
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
