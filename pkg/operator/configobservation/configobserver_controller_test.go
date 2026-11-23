package configobservation

import (
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"

	configv1 "github.com/openshift/api/config/v1"
	features "github.com/openshift/api/features"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
)

func apiServerListers(t *testing.T, apiServer *configv1.APIServer) Listers {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if apiServer != nil {
		if err := indexer.Add(apiServer); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	return Listers{apiServerLister: configlistersv1.NewAPIServerLister(indexer)}
}

func TestObserveTLSSecurityProfile(t *testing.T) {
	// Modern has a single cipher suite and a well-known group list, which keeps
	// the expectations below short.
	modernAPIServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
		},
	}

	tests := []struct {
		name                     string
		featureGateAccessor      featuregates.FeatureGateAccess
		expectCurvePreferences   bool
		expectUnchangedOnFailure bool
	}{
		{
			name:                "TLSGroupPreferences disabled",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(nil, []configv1.FeatureGateName{features.FeatureGateTLSGroupPreferences}),
		},
		{
			name:                   "TLSGroupPreferences enabled",
			featureGateAccessor:    featuregates.NewHardcodedFeatureGateAccess([]configv1.FeatureGateName{features.FeatureGateTLSGroupPreferences}, nil),
			expectCurvePreferences: true,
		},
		{
			name: "feature gates unavailable",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccessForTesting(
				[]configv1.FeatureGateName{features.FeatureGateTLSGroupPreferences}, nil, make(chan struct{}), errors.New("not observed yet")),
			expectUnchangedOnFailure: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			existingConfig := map[string]interface{}{
				"servingInfo": map[string]interface{}{"minTLSVersion": "VersionTLS10"},
			}
			observed, errs := observeTLSSecurityProfile(test.featureGateAccessor)(
				apiServerListers(t, modernAPIServer),
				events.NewInMemoryRecorder("observetlssecurityprofile_test", clock.RealClock{}),
				existingConfig,
			)

			if test.expectUnchangedOnFailure {
				if len(errs) == 0 {
					t.Fatal("expected an error when the feature gates cannot be read")
				}
				if !equality.Semantic.DeepEqual(existingConfig, observed) {
					t.Fatalf("expected the existing config to be preserved, got %v", observed)
				}
				return
			}
			if len(errs) > 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}

			minTLSVersion, found, err := unstructured.NestedString(observed, "servingInfo", "minTLSVersion")
			if err != nil || !found {
				t.Fatalf("expected servingInfo.minTLSVersion to be observed (found=%t, err=%v)", found, err)
			}
			if expected := string(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion); minTLSVersion != expected {
				t.Errorf("expected minTLSVersion %q, got %q", expected, minTLSVersion)
			}
			if cipherSuites, found, err := unstructured.NestedStringSlice(observed, "servingInfo", "cipherSuites"); err != nil || !found || len(cipherSuites) == 0 {
				t.Errorf("expected servingInfo.cipherSuites to be observed, got %v (found=%t, err=%v)", cipherSuites, found, err)
			}

			// servingInfo.groups must never be observed: the controller's config
			// schema only understands curvePreferences.
			if _, found, err := unstructured.NestedFieldNoCopy(observed, "servingInfo", "groups"); err != nil || found {
				t.Errorf("servingInfo.groups should never be set in the observed config: %v", observed)
			}

			curvePreferences, found, err := unstructured.NestedSlice(observed, "servingInfo", "curvePreferences")
			if err != nil {
				t.Fatalf("unexpected error reading servingInfo.curvePreferences: %v", err)
			}
			if !test.expectCurvePreferences {
				if found {
					t.Errorf("expected no servingInfo.curvePreferences with the feature gate disabled, got %v", curvePreferences)
				}
				return
			}
			if !found || len(curvePreferences) == 0 {
				t.Fatalf("expected servingInfo.curvePreferences to be observed, got %v (found=%t)", curvePreferences, found)
			}
			for i, curvePreference := range curvePreferences {
				if _, ok := curvePreference.(int64); !ok {
					t.Errorf("expected curve preference at index %d to be an int64, got %T", i, curvePreference)
				}
			}
		})
	}
}
