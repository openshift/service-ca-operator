package controller

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	appslistersv1 "k8s.io/client-go/listers/apps/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

func TestStatefulSetSecretRequiresRegenerationOrReplace(t *testing.T) {
	tests := []struct {
		name               string
		primeStatefulSet   func(cache.Indexer)
		secret             *v1.Secret
		expected           bool
		statefulSetIsValid bool
	}{
		{
			name:             "no StatefulSet annotation",
			primeStatefulSet: func(statefulSetCache cache.Indexer) {},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1", Name: "mysecret",
					Annotations: map[string]string{},
				},
			},
			expected:           false,
			statefulSetIsValid: false,
		},
		{
			name:             "missing StatefulSet",
			primeStatefulSet: func(statefulSetCache cache.Indexer) {},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1", Name: "mysecret",
					Annotations: map[string]string{
						api.AlphaStatefulSetNameAnnotation: "foo",
					},
				},
			},
			expected:           false,
			statefulSetIsValid: false,
		},
		{
			name: "StatefulSet-uid-mismatch",
			primeStatefulSet: func(statefulSetCache cache.Indexer) {
				statefulSetCache.Add(&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "foo", UID: types.UID("uid-2"), Annotations: map[string]string{api.AlphaServingCertSecretAnnotation: "mysecret"}},
				})
			},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1", Name: "mysecret",
					Annotations: map[string]string{
						api.AlphaStatefulSetNameAnnotation: "foo",
						api.AlphaStatefulSetUIDAnnotation:  "uid-1",
					},
					OwnerReferences: []metav1.OwnerReference{statefulSetOwnerRef(&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: types.UID("uid-2")}})},
				},
			},
			expected:           false,
			statefulSetIsValid: false,
		},
		{
			name: "StatefulSet secret name mismatch",
			primeStatefulSet: func(statefulSetCache cache.Indexer) {
				statefulSetCache.Add(&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "foo", UID: types.UID("uid-1"), Annotations: map[string]string{api.AlphaServingCertSecretAnnotation: "mysecret2"}},
				})
			},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1", Name: "mysecret",
					Annotations: map[string]string{
						api.AlphaStatefulSetNameAnnotation: "foo",
						api.AlphaStatefulSetUIDAnnotation:  "uid-1",
					},
					OwnerReferences: []metav1.OwnerReference{statefulSetOwnerRef(&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: types.UID("uid-1")}})},
				},
			},
			expected:           false,
			statefulSetIsValid: false,
		},
		{
			name: "no expiry",
			primeStatefulSet: func(statefulSetCache cache.Indexer) {
				statefulSetCache.Add(&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "foo", UID: types.UID("uid-1"), Annotations: map[string]string{api.AlphaServingCertSecretAnnotation: "mysecret"}},
				})
			},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1", Name: "mysecret",
					Annotations: map[string]string{
						api.AlphaStatefulSetNameAnnotation: "foo",
						api.AlphaStatefulSetUIDAnnotation:  "uid-1",
					},
					OwnerReferences: []metav1.OwnerReference{statefulSetOwnerRef(&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: types.UID("uid-1")}})},
				},
			},
			statefulSetIsValid: true,
			expected:           true,
		},
		{
			name: "bad expiry",
			primeStatefulSet: func(statefulSetCache cache.Indexer) {
				statefulSetCache.Add(&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "foo", UID: types.UID("uid-1"), Annotations: map[string]string{api.AlphaServingCertSecretAnnotation: "mysecret"}},
				})
			},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1", Name: "mysecret",
					Annotations: map[string]string{
						api.AlphaStatefulSetNameAnnotation:   "foo",
						api.AlphaStatefulSetUIDAnnotation:    "uid-1",
						api.AlphaServingCertExpiryAnnotation: "bad-format",
					},
					OwnerReferences: []metav1.OwnerReference{statefulSetOwnerRef(&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: types.UID("uid-1")}})},
				},
			},
			expected:           true,
			statefulSetIsValid: true,
		},
		{
			name: "expired expiry",
			primeStatefulSet: func(statefulSetCache cache.Indexer) {
				statefulSetCache.Add(&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "foo", UID: types.UID("uid-1"), Annotations: map[string]string{api.AlphaServingCertSecretAnnotation: "mysecret"}},
				})
			},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1", Name: "mysecret",
					Annotations: map[string]string{
						api.AlphaStatefulSetNameAnnotation:   "foo",
						api.AlphaStatefulSetUIDAnnotation:    "uid-1",
						api.AlphaServingCertExpiryAnnotation: time.Now().Add(-30 * time.Minute).Format(time.RFC3339),
					},
					OwnerReferences: []metav1.OwnerReference{statefulSetOwnerRef(&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: types.UID("uid-1")}})},
				},
			},
			expected:           true,
			statefulSetIsValid: true,
		},
		{
			name: "distant expiry",
			primeStatefulSet: func(statefulSetCache cache.Indexer) {
				statefulSetCache.Add(&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "foo", UID: types.UID("uid-1"), Annotations: map[string]string{api.AlphaServingCertSecretAnnotation: "mysecret"}},
				})
			},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1", Name: "mysecret",
					Annotations: map[string]string{
						api.AlphaStatefulSetNameAnnotation:   "foo",
						api.AlphaStatefulSetUIDAnnotation:    "uid-1",
						api.AlphaServingCertExpiryAnnotation: time.Now().Add(90 * time.Minute).Format(time.RFC3339),
					},
					OwnerReferences: []metav1.OwnerReference{statefulSetOwnerRef(&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: types.UID("uid-1")}})},
				},
				Data: map[string][]byte{
					v1.TLSCertKey:       []byte("content"),
					v1.TLSPrivateKeyKey: []byte("morecontent"),
				},
			},
			expected:           false,
			statefulSetIsValid: true,
		},
		{
			name: "missing ownerref",
			primeStatefulSet: func(statefulSetCache cache.Indexer) {
				statefulSetCache.Add(&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "foo", UID: types.UID("uid-1"), Annotations: map[string]string{api.AlphaServingCertSecretAnnotation: "mysecret"}},
				})
			},
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns1", Name: "mysecret",
					Annotations: map[string]string{
						api.AlphaStatefulSetNameAnnotation:   "foo",
						api.AlphaStatefulSetUIDAnnotation:    "uid-1",
						api.AlphaServingCertExpiryAnnotation: time.Now().Add(90 * time.Minute).Format(time.RFC3339),
					},
					OwnerReferences: []metav1.OwnerReference{statefulSetOwnerRef(&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: types.UID("uid-2")}})},
				},
			},
			expected:           true,
			statefulSetIsValid: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			index := cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			c := &statefulSetServingCertUpdateController{
				statefulSetLister: appslistersv1.NewStatefulSetLister(index),
				secretLister:      listers.NewSecretLister(index),
			}
			tc.primeStatefulSet(index)
			statefulSet := c.getStatefulSetForSecret(tc.secret)
			if statefulSet == nil {
				if tc.expected {
					t.Errorf("%s: should have returned StatefulSet", tc.name)
				}
			} else {
				isValid := isSecretValidForStatefulSet(statefulSet, tc.secret)
				if tc.statefulSetIsValid != isValid {
					t.Errorf("isSecretValidForStatefulSet result: %v unexpected", isValid)
				}
				if tc.statefulSetIsValid {
					minTimeLeft := 1 * time.Hour
					actualRegen := c.requiresRegeneration(statefulSet, tc.secret, minTimeLeft)
					if tc.expected != actualRegen {
						t.Errorf("%s: expected %v, got %v", tc.name, tc.expected, actualRegen)
					}
				}
			}
		})
	}
}
