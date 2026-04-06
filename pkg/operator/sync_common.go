package operator

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/openshift/library-go/pkg/pki"
	"github.com/openshift/service-ca-operator/pkg/operator/metrics"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/service-ca-operator/bindata"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

func (c *serviceCAOperator) manageControllerNS(ctx context.Context) (bool, error) {
	_, modified, err := resourceapply.ApplyNamespace(ctx, c.corev1Client, c.eventRecorder, resourceread.ReadNamespaceV1OrDie(bindata.MustAsset("assets/ns.yaml")))
	return modified, err
}

func (c *serviceCAOperator) manageControllerResources(ctx context.Context, modified *bool) error {
	var err error
	requiredClusterRole := resourceread.ReadClusterRoleV1OrDie(bindata.MustAsset("assets/clusterrole.yaml"))
	_, mod, err := resourceapply.ApplyClusterRole(ctx, c.rbacv1Client, c.eventRecorder, requiredClusterRole)
	if err != nil {
		return err
	}
	*modified = *modified || mod

	requiredClusterRoleBinding := resourceread.ReadClusterRoleBindingV1OrDie(bindata.MustAsset("assets/clusterrolebinding.yaml"))
	_, mod, err = resourceapply.ApplyClusterRoleBinding(ctx, c.rbacv1Client, c.eventRecorder, requiredClusterRoleBinding)
	if err != nil {
		return err
	}
	*modified = *modified || mod

	requiredRole := resourceread.ReadRoleV1OrDie(bindata.MustAsset("assets/role.yaml"))
	_, mod, err = resourceapply.ApplyRole(ctx, c.rbacv1Client, c.eventRecorder, requiredRole)
	if err != nil {
		return err
	}
	*modified = *modified || mod

	requiredRoleBinding := resourceread.ReadRoleBindingV1OrDie(bindata.MustAsset("assets/rolebinding.yaml"))
	_, mod, err = resourceapply.ApplyRoleBinding(ctx, c.rbacv1Client, c.eventRecorder, requiredRoleBinding)
	if err != nil {
		return err
	}
	*modified = *modified || mod

	requiredSA := resourceread.ReadServiceAccountV1OrDie(bindata.MustAsset("assets/sa.yaml"))
	_, mod, err = resourceapply.ApplyServiceAccount(ctx, c.corev1Client, c.eventRecorder, requiredSA)
	if err != nil {
		return err
	}
	*modified = *modified || mod

	return nil
}

func (c *serviceCAOperator) manageSignerCA(ctx context.Context, rawUnsupportedServiceCAConfig []byte) (bool, error) {
	secret := resourceread.ReadSecretV1OrDie(bindata.MustAsset("assets/signing-secret.yaml"))

	var existingCert *x509.Certificate
	existing, err := c.corev1Client.Secrets(secret.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Secret will need to be created
	} else if err != nil {
		return false, err
	} else {
		// Secret exists - attempt to parse its certs
		certData := existing.Data[corev1.TLSCertKey]
		if len(certData) > 0 {
			certs, err := cert.ParseCertsPEM(certData)
			if err != nil {
				return false, err
			}
			if len(certs) > 0 {
				existingCert = certs[0]
			}
		}
	}

	serviceCAConfig, err := loadUnsupportedServiceCAConfig(rawUnsupportedServiceCAConfig)
	if err != nil {
		return false, fmt.Errorf("failed to load unsupportedConfigOverrides: %v", err)
	}

	rotationMsg := ""
	if existingCert == nil {
		// Secret does not exist or lacks the expected cert.
		validityDuration := serviceCAConfig.CAConfig.ValidityDurationForTesting
		if err := c.initializeSigningSecret(secret, validityDuration, c.signingCertificateLifetime); err != nil {
			return false, err
		}
	} else {
		rotationMsg, err = c.maybeRotateSigningSecret(existing, existingCert, serviceCAConfig, c.minimumTrustDuration, c.signingCertificateLifetime)
		if err != nil {
			return false, fmt.Errorf("failed to rotate signing CA: %v", err)
		}
		if len(rotationMsg) == 0 {
			metrics.SetCAExpiry(existingCert.NotAfter)
			return false, nil
		}
		// Ensure the updated existing secret is applied below
		secret = existing
	}

	certs, err := cert.ParseCertsPEM(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return false, err
	}
	metrics.SetCAExpiry(certs[0].NotAfter)

	_, mod, err := resourceapply.ApplySecret(ctx, c.corev1Client, c.eventRecorder, secret)

	if err == nil && len(rotationMsg) > 0 {
		c.eventRecorder.Eventf("ServiceCARotated", rotationMsg)
	}

	return mod, err
}

// initializeSigningSecret updates the provided secret with the
// PEM-encoded certificate and private key of a new self-signed
// CA. The duration, if non-zero, will be used to set the
// expiry of the CA.
func (c *serviceCAOperator) initializeSigningSecret(secret *corev1.Secret, duration time.Duration, lifetime time.Duration) error {
	name := serviceServingCertSignerName()
	klog.V(4).Infof("generating signing CA: %s", name)

	var ca *crypto.TLSCertificateConfig
	var err error
	// When configurable PKI is enabled, attempt to resolve a certificate
	// config from the PKI profile. A nil config (Unmanaged mode) means
	// no custom key configuration is active, so fall through to the
	// legacy code path.
	if c.configurablePKIEnabled {
		var certificateCfg *pki.CertificateConfig
		certificateCfg, err = pki.ResolveCertificateConfig(c.pkiProvider, pki.CertificateTypeSigner, "service-ca.service-serving-signer")
		// TODO: This NotFound fallback may be temporary while ConfigurablePKI
		// is in tech preview. Once the installer provides the initial "cluster"
		// PKI resource, this fallback may no longer be needed.
		if apierrors.IsNotFound(err) {
			klog.V(2).Infof("PKI resource not found, using default PKI profile")
			defaultProfile := pki.DefaultPKIProfile()
			defaultProvider := pki.NewStaticPKIProfileProvider(&defaultProfile)
			certificateCfg, err = pki.ResolveCertificateConfig(defaultProvider, pki.CertificateTypeSigner, "service-ca.service-serving-signer")
		}
		if err != nil {
			return fmt.Errorf("failed to resolve PKI certificate config: %w", err)
		}
		if certificateCfg != nil {
			ca, err = crypto.NewSigningCertificate(name, certificateCfg.Key, crypto.WithLifetime(lifetime))
			if err != nil {
				return err
			}
		}
	}
	// Fall back to legacy cert generation when configurable PKI is
	// disabled or the PKI profile is Unmanaged (nil config).
	if ca == nil {
		ca, err = crypto.MakeSelfSignedCAConfig(name, lifetime)
	}
	if err != nil {
		return err
	}

	// Set a custom expiry if one was provided
	ca, err = maybeUpdateExpiry(ca, duration)
	if err != nil {
		return fmt.Errorf("error renewing ca for custom duration: %v", err)
	}

	certBuff := &bytes.Buffer{}
	keyBuff := &bytes.Buffer{}
	if err := ca.WriteCertConfig(certBuff, keyBuff); err != nil {
		return err
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[corev1.TLSCertKey] = certBuff.Bytes()
	secret.Data[corev1.TLSPrivateKeyKey] = keyBuff.Bytes()
	return nil
}

func (c *serviceCAOperator) manageSignerCABundle(ctx context.Context, forceUpdate bool) (bool, error) {
	configMap := resourceread.ReadConfigMapV1OrDie(bindata.MustAsset("assets/signing-cabundle.yaml"))
	if !forceUpdate {
		// We don't need to force an update; return if the configmap already exists (or error getting).
		_, err := c.corev1Client.ConfigMaps(configMap.Namespace).Get(ctx, configMap.Name, metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			return false, err
		}
	}

	klog.V(4).Infof("updating CA bundle configmap")
	secret := resourceread.ReadSecretV1OrDie(bindata.MustAsset("assets/signing-secret.yaml"))
	currentSigningKeySecret, err := c.corev1Client.Secrets(secret.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
	// Return err or if the signing secret has no data (should not normally happen).
	if err != nil || len(currentSigningKeySecret.Data[corev1.TLSCertKey]) == 0 {
		return false, err
	}

	// Prefer the full bundle after rotation since it contains all required CAs.
	bundle := currentSigningKeySecret.Data[api.BundleDataKey]
	if len(bundle) == 0 {
		bundle = currentSigningKeySecret.Data[corev1.TLSCertKey]
	}
	configMap.Data[api.BundleDataKey] = string(bundle)

	_, mod, err := resourceapply.ApplyConfigMap(ctx, c.corev1Client, c.eventRecorder, configMap)
	return mod, err
}

func (c *serviceCAOperator) manageDeployment(ctx context.Context, options *operatorv1.ServiceCA, forceDeployment, runOnWorkers bool) (bool, error) {
	required := resourceread.ReadDeploymentV1OrDie(bindata.MustAsset("assets/deployment.yaml"))
	required.Spec.Template.Spec.Containers[0].Image = os.Getenv("CONTROLLER_IMAGE")
	required.Spec.Template.Spec.Containers[0].Args = append(required.Spec.Template.Spec.Containers[0].Args, fmt.Sprintf("-v=%d", loglevel.LogLevelToVerbosity(options.Spec.LogLevel)))
	for i := range required.Spec.Template.Spec.Containers[0].Env {
		if required.Spec.Template.Spec.Containers[0].Env[i].Name == operatorVersionEnvName {
			required.Spec.Template.Spec.Containers[0].Env[i].Value = os.Getenv(operatorVersionEnvName)
			break
		}
	}

	if c.shortCertRotationEnabled {
		required.Spec.Template.Spec.Containers[0].Args = append(required.Spec.Template.Spec.Containers[0].Args, "--feature-gates=ShortCertRotation=true")
	}

	if runOnWorkers {
		required.Spec.Template.Spec.NodeSelector = map[string]string{}
	}

	if err := resourceapply.SetSpecHashAnnotation(&required.ObjectMeta, required.Spec); err != nil {
		return false, fmt.Errorf("failed to count hash for deployment spec: %w", err)
	}

	deployment, mod, err := resourceapply.ApplyDeploymentWithForce(ctx, c.appsv1Client, c.eventRecorder, required, resourcemerge.ExpectedDeploymentGeneration(required, options.Status.Generations), forceDeployment)
	if err != nil {
		return mod, err
	}
	resourcemerge.SetDeploymentGeneration(&options.Status.Generations, deployment)

	return mod, nil
}

func serviceServingCertSignerName() string {
	return fmt.Sprintf("%s@%d", "openshift-service-serving-signer", time.Now().Unix())
}
