package operator

import (
	"bytes"
	"fmt"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsclientv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
	"github.com/openshift/service-ca-operator/pkg/operator/v4_00_assets"
	"github.com/golang/glog"
)

func manageControllerNS(c serviceCAOperator) (bool, error) {
	_, modified, err := resourceapply.ApplyNamespace(c.corev1Client, c.eventRecorder, resourceread.ReadNamespaceV1OrDie(v4_00_assets.MustAsset("v4.0.0/service-serving-cert-signer-controller/ns.yaml")))
	return modified, err
}

func manageSignerControllerResources(c serviceCAOperator) (bool, string) {
	return manageControllerResources(c, "v4.0.0/service-serving-cert-signer-controller/")
}

func manageAPIServiceControllerResources(c serviceCAOperator) (bool, string) {
	return manageControllerResources(c, "v4.0.0/apiservice-cabundle-controller/")
}

func manageConfigMapCABundleControllerResources(c serviceCAOperator) (bool, string) {
	return manageControllerResources(c, "v4.0.0/configmap-cabundle-controller/")
}

func manageControllerResources(c serviceCAOperator, resourcePath string) (bool, string) {
	var err error
	requiredClusterRole := resourceread.ReadClusterRoleV1OrDie(v4_00_assets.MustAsset(resourcePath + "clusterrole.yaml"))
	_, _, err = resourceapply.ApplyClusterRole(c.rbacv1Client, c.eventRecorder, requiredClusterRole)
	if err != nil {
		return false, "clusterrole"
	}

	requiredClusterRoleBinding := resourceread.ReadClusterRoleBindingV1OrDie(v4_00_assets.MustAsset(resourcePath + "clusterrolebinding.yaml"))
	_, _, err = resourceapply.ApplyClusterRoleBinding(c.rbacv1Client, c.eventRecorder, requiredClusterRoleBinding)
	if err != nil {
		return false, "clusterrolebinding"
	}

	requiredRole := resourceread.ReadRoleV1OrDie(v4_00_assets.MustAsset(resourcePath + "role.yaml"))
	_, _, err = resourceapply.ApplyRole(c.rbacv1Client, c.eventRecorder, requiredRole)
	if err != nil {
		return false, "role"
	}

	requiredRoleBinding := resourceread.ReadRoleBindingV1OrDie(v4_00_assets.MustAsset(resourcePath + "rolebinding.yaml"))
	_, _, err = resourceapply.ApplyRoleBinding(c.rbacv1Client, c.eventRecorder, requiredRoleBinding)
	if err != nil {
		return false, "rolebinding"
	}

	requiredSA := resourceread.ReadServiceAccountV1OrDie(v4_00_assets.MustAsset(resourcePath + "sa.yaml"))
	_, saModified, err := resourceapply.ApplyServiceAccount(c.corev1Client, c.eventRecorder, requiredSA)
	if err != nil {
		return false, "serviceaccount"
	}

	return saModified, ""
}

func manageSignerCA(c serviceCAOperator) (*corev1.Secret, bool, error) {
	secret := resourceread.ReadSecretV1OrDie(v4_00_assets.MustAsset("v4.0.0/service-serving-cert-signer-controller/signing-secret.yaml"))
	existing, err := c.corev1Client.Secrets(secret.Namespace).Get(secret.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return existing, false, err
	}

	if !apierrors.IsNotFound(err) {
		glog.Infof("signer secret %s/%s found\n", secret.Namespace, secret.Name)
		if c.ca == nil {
			// Create the CA cache, we would hit this if the operator restarts.
			glog.Infof("initially loading signer secret\n")
			newCA, caErr := crypto.GetCAFromBytes(existing.Data["tls.crt"], existing.Data["tls.key"])
			if caErr != nil {
				return existing, false, caErr
			}
			c.ca = newCA
		}

		// Check if the CA cache matches the secret, if not, continue with CA generation below.
		isCurrent, curCAErr := isCurrentCA(c, existing)
		if curCAErr != nil {
			return existing, false, curCAErr
		}
		if isCurrent {
			glog.Infof("signer secret is current\n")
			return existing, false, nil
		}
	}

	ca, err := crypto.MakeSelfSignedCAConfig(serviceServingCertSignerName(), 365)
	if err != nil {
		return existing, false, err
	}

	certBytes := &bytes.Buffer{}
	keyBytes := &bytes.Buffer{}
	if err := ca.WriteCertConfig(certBytes, keyBytes); err != nil {
		return existing, false, err
	}

	secret.Data["tls.crt"] = certBytes.Bytes()
	secret.Data["tls.key"] = keyBytes.Bytes()
	newCA, caErr := crypto.GetCAFromBytes(certBytes.Bytes(), keyBytes.Bytes())
	if caErr != nil {
		return existing, false, caErr
	}

	s, ok, err := resourceapply.ApplySecret(c.corev1Client, c.eventRecorder, secret)
	if err == nil {
		// Only update the CA cache if the secret was properly updated.
		glog.Infof("updated CA cache\n")
		c.ca = newCA
	}
	glog.Infof("regenerated new CA\n")
	return s, ok, err
}

func manageSignerCABundle(c serviceCAOperator) (*corev1.ConfigMap, bool, error) {
	configMap := resourceread.ReadConfigMapV1OrDie(v4_00_assets.MustAsset("v4.0.0/apiservice-cabundle-controller/signing-cabundle.yaml"))
	// Fetch the cached CA.
	caCert, _, err := c.ca.Config.GetPEMBytes()
	if err != nil {
		return nil, false, err
	}

	existing, err := c.corev1Client.ConfigMaps(configMap.Namespace).Get(configMap.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return existing, false, err
	}
	if !apierrors.IsNotFound(err) {
		// Check if the CA bundle is the same as cache, otherwise continue with update.
		if configMap.Data["ca-bundle.crt"] == string(caCert) {
			glog.Infof("CA bundle is cached\n")
			return existing, false, err
		}
	}

	//secret := resourceread.ReadSecretV1OrDie(v4_00_assets.MustAsset("v4.0.0/service-serving-cert-signer-controller/signing-secret.yaml"))
	//currentSigningKeySecret, err := c.corev1Client.Secrets(secret.Namespace).Get(secret.Name, metav1.GetOptions{})
	//if err != nil || len(currentSigningKeySecret.Data["tls.crt"]) == 0 {
	//	return existing, false, err
	//}

	configMap.Data["ca-bundle.crt"] = string(caCert)
	glog.Infof("updated CA bundle\n")
	return resourceapply.ApplyConfigMap(c.corev1Client, c.eventRecorder, configMap)
}

func manageSignerControllerConfig(client coreclientv1.ConfigMapsGetter, eventRecorder events.Recorder) (*corev1.ConfigMap, bool, error) {
	configMap := resourceread.ReadConfigMapV1OrDie(v4_00_assets.MustAsset("v4.0.0/service-serving-cert-signer-controller/cm.yaml"))
	defaultConfig := v4_00_assets.MustAsset("v4.0.0/service-serving-cert-signer-controller/defaultconfig.yaml")
	requiredConfigMap, _, err := resourcemerge.MergeConfigMap(configMap, "controller-config.yaml", nil, defaultConfig)
	if err != nil {
		return nil, false, err
	}
	return resourceapply.ApplyConfigMap(client, eventRecorder, requiredConfigMap)
}

func manageAPIServiceControllerConfig(client coreclientv1.ConfigMapsGetter, eventRecorder events.Recorder) (*corev1.ConfigMap, bool, error) {
	configMap := resourceread.ReadConfigMapV1OrDie(v4_00_assets.MustAsset("v4.0.0/apiservice-cabundle-controller/cm.yaml"))
	defaultConfig := v4_00_assets.MustAsset("v4.0.0/apiservice-cabundle-controller/defaultconfig.yaml")
	requiredConfigMap, _, err := resourcemerge.MergeConfigMap(configMap, "controller-config.yaml", nil, defaultConfig)
	if err != nil {
		return nil, false, err
	}
	return resourceapply.ApplyConfigMap(client, eventRecorder, requiredConfigMap)
}

func manageConfigMapCABundleControllerConfig(client coreclientv1.ConfigMapsGetter, eventRecorder events.Recorder) (*corev1.ConfigMap, bool, error) {
	configMap := resourceread.ReadConfigMapV1OrDie(v4_00_assets.MustAsset("v4.0.0/configmap-cabundle-controller/cm.yaml"))
	defaultConfig := v4_00_assets.MustAsset("v4.0.0/configmap-cabundle-controller/defaultconfig.yaml")
	requiredConfigMap, _, err := resourcemerge.MergeConfigMap(configMap, "controller-config.yaml", nil, defaultConfig)
	if err != nil {
		return nil, false, err
	}
	return resourceapply.ApplyConfigMap(client, eventRecorder, requiredConfigMap)
}

func manageSignerControllerDeployment(client appsclientv1.AppsV1Interface, eventRecorder events.Recorder, options *operatorv1.ServiceCA, forceDeployment bool) (*appsv1.Deployment, bool, error) {
	return manageDeployment(client, eventRecorder, options, "v4.0.0/service-serving-cert-signer-controller/", forceDeployment)
}

func manageAPIServiceControllerDeployment(client appsclientv1.AppsV1Interface, eventRecorder events.Recorder, options *operatorv1.ServiceCA, forceDeployment bool) (*appsv1.Deployment, bool, error) {
	return manageDeployment(client, eventRecorder, options, "v4.0.0/apiservice-cabundle-controller/", forceDeployment)
}

func manageConfigMapCABundleControllerDeployment(client appsclientv1.AppsV1Interface, eventRecorder events.Recorder, options *operatorv1.ServiceCA, forceDeployment bool) (*appsv1.Deployment, bool, error) {
	return manageDeployment(client, eventRecorder, options, "v4.0.0/configmap-cabundle-controller/", forceDeployment)
}

func manageDeployment(client appsclientv1.AppsV1Interface, eventRecorder events.Recorder, options *operatorv1.ServiceCA, resourcePath string, forceDeployment bool) (*appsv1.Deployment, bool, error) {
	required := resourceread.ReadDeploymentV1OrDie(v4_00_assets.MustAsset(resourcePath + "deployment.yaml"))
	required.Spec.Template.Spec.Containers[0].Image = os.Getenv("CONTROLLER_IMAGE")
	required.Spec.Template.Spec.Containers[0].Args = append(required.Spec.Template.Spec.Containers[0].Args, fmt.Sprintf("-v=%s", options.Spec.LogLevel))

	return resourceapply.ApplyDeployment(client, eventRecorder, required, getGeneration(client, operatorclient.TargetNamespace, required.Name), forceDeployment)
}

func serviceServingCertSignerName() string {
	return fmt.Sprintf("%s@%d", "openshift-service-serving-signer", time.Now().Unix())
}

// isCurrentCA compares the operator CA cache against the given secret and returns true if they match.
func isCurrentCA(c serviceCAOperator, secret *corev1.Secret) (bool, error) {
	curCACert, curCAKey, err := c.ca.Config.GetPEMBytes()
	if err != nil {
		return false, err
	}
	secretCert := secret.Data["tls.crt"]
	secretKey := secret.Data["tls.key"]
	if len(secretCert) == 0 || len(secretKey) == 0 {
		return false, nil
	}

	return bytes.Equal(curCACert, secretCert) && bytes.Equal(curCAKey, secretKey), nil
}
