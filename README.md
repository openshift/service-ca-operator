# OpenShift Service CA Operator

This operator runs the following OpenShift controllers:
* **serving cert signer:**
  * Issues a signed serving certificate/key pair to services annotated with 'service.beta.openshift.io/serving-cert-secret-name' via a secret. [See the current OKD documentation for usage.](https://docs.okd.io/latest/dev_guide/secrets.html#service-serving-certificate-secrets)

* **configmap cabundle injector:**
  * Watches for configmaps annotated with 'service.beta.openshift.io/inject-cabundle=true' and adds or updates a data item (key "service-ca.crt") containing the PEM-encoded CA signing bundle. Consumers of the configmap can then trust service-ca.crt in their TLS client configuration, allowing connections to services that utilize service-serving certificates.
  * Note: Explicitly referencing the "service-ca.crt" key in a volumeMount will prevent a pod from starting until the configMap has been injected with the CA bundle (https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/#restrictions). This behavior helps ensure that pods start with the CA bundle data available.

```
$ oc create configmap foobar --from-literal=key1=foo
configmap/foobar created
$ oc get configmap/foobar -o yaml
apiVersion: v1
data:
  key1: foo
kind: ConfigMap
metadata:
  creationTimestamp: 2018-09-11T23:44:56Z
  name: foobar
  namespace: myproject
  resourceVersion: "56490"
  selfLink: /api/v1/namespaces/myproject/configmaps/foobar
  uid: afee501b-b61c-11e8-833b-c85b762603b0
$ oc annotate configmap foobar service.beta.openshift.io/inject-cabundle="true"
configmap/foobar annotated
$ oc get configmap/foobar -o yaml
apiVersion: v1
data:
  key1: foo
  service-ca.crt: |
    -----BEGIN CERTIFICATE-----
    MIIDCjCCAfKgAwIBAgIBATANBgkqhkiG9w0BAQsFADA2MTQwMgYDVQQDDCtvcGVu
    c2hpZnQtc2VydmljZS1zZXJ2aW5nLXNpZ25lckAxNTM2Njk1NTIxMB4XDTE4MDkx
    MTE5NTIwMVoXDTIzMDkxMDE5NTIwMlowNjE0MDIGA1UEAwwrb3BlbnNoaWZ0LXNl
    cnZpY2Utc2VydmluZy1zaWduZXJAMTUzNjY5NTUyMTCCASIwDQYJKoZIhvcNAQEB
    BQADggEPADCCAQoCggEBANP9Asc657SkWVPOohmMlrXQirl7taaarmM5l3/pNgeo
    /fwkaH5KrJ9D8OxiSd5aepURrxeAk22U9eicGWRNssoe1wukE4hlLcIUlwdvElBA
    5dS0xRI3Jld3WjqisVRdjTy9O4GEWFOIhkZlrL9ZcNWe8WhiCtn447rgI1QhtZtX
    mAxUZ/mZdswQgvP0eqWOGWarC1b+RBQFo7uF0No6N4vTlpNBCxoz3CYvlpXwODYU
    4dpdpsoF6PdZ+8uMh4hVY/2w1/6qgwwe4E85RkumBwyPHQGOFKkJDF26nBLM1HGF
    +BLCcpUatISgLO9eDm1thcDvmash9HmaH7nJ+195ck0CAwEAAaMjMCEwDgYDVR0P
    AQH/BAQDAgKkMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABwA
    aZNHvhla0QWznreqkPkd1bUbMit4R5JbTGYk6cd37zLAWA60inwaZ0A4GFk7VVom
    Zbru3/DdhoI4ojcY26eqY0CbrhizV10mlI8Q/cdu1EKpDFwrHiwNk2rsBVbox8Es
    Quy9jgb51WIFhUy4C0aqSmc495Gg9pCxzs4cCuqJtb8OyUEUBKbxyz9lA1a7ZUpx
    BofBpbbyBRtnf27mQTyxVcZBzkHAj1Ouq0mBiXs4c3YLGbNse00MP0G6Uwtmsbev
    PCmHDAHzPvb7N9vMZ4jrqulkaN1S2H9091pH0DxA8srUl0JCuB7p03uPrxCOSAwT
    6OkzAWkPxzToypA+7fU=
    -----END CERTIFICATE-----
kind: ConfigMap
metadata:
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
  creationTimestamp: 2018-09-11T23:44:56Z
  name: foobar
  namespace: myproject
  resourceVersion: "56606"
  selfLink: /api/v1/namespaces/myproject/configmaps/foobar
  uid: afee501b-b61c-11e8-833b-c85b762603b0
```

* **generic cabundle injector:**
  * Watches for apiservices, mutatingwebhookconfig, validatingwebhookconfig and crds annotated with 'service.beta.openshift.io/inject-cabundle=true' and sets the appropriate ca bundle field (apiservice -> spec.caBundle, *webhookconfig -> webhooks[].clientConfig.caBundle, spec.conversion.webhook.clientConfig.caBundle) with a base64url-encoded CA signing bundle. The following example is for apiservices:

```
$ oc get apiservice/v1.build.openshift.io -o yaml
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"apiregistration.k8s.io/v1beta1","kind":"APIService","metadata":{"annotations":{"service.beta.openshift.io/inject-cabundle":"true"},"name":"v1.build.openshift.io","namespace":""},"spec":{"group":"build.openshift.io","groupPriorityMinimum":9900,"service":{"name":"api","namespace":"openshift-apiserver"},"version":"v1","versionPriority":15}}
    service.beta.openshift.io/inject-cabundle: "true"
  creationTimestamp: 2018-09-11T19:52:16Z
  name: v1.build.openshift.io
  resourceVersion: "923"
  selfLink: /apis/apiregistration.k8s.io/v1/apiservices/v1.build.openshift.io
  uid: 2f55ec88-b5fc-11e8-833b-c85b762603b0
spec:
  caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURDakNDQWZLZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREEyTVRRd01nWURWUVFEREN0dmNHVnUKYzJocFpuUXRjMlZ5ZG1salpTMXpaWEoyYVc1bkxYTnBaMjVsY2tBeE5UTTJOamsxTlRJeE1CNFhEVEU0TURreApNVEU1TlRJd01Wb1hEVEl6TURreE1ERTVOVEl3TWxvd05qRTBNRElHQTFVRUF3d3JiM0JsYm5Ob2FXWjBMWE5sCmNuWnBZMlV0YzJWeWRtbHVaeTF6YVdkdVpYSkFNVFV6TmpZNU5UVXlNVENDQVNJd0RRWUpLb1pJaHZjTkFRRUIKQlFBRGdnRVBBRENDQVFvQ2dnRUJBTlA5QXNjNjU3U2tXVlBPb2htTWxyWFFpcmw3dGFhYXJtTTVsMy9wTmdlbwovZndrYUg1S3JKOUQ4T3hpU2Q1YWVwVVJyeGVBazIyVTllaWNHV1JOc3NvZTF3dWtFNGhsTGNJVWx3ZHZFbEJBCjVkUzB4UkkzSmxkM1dqcWlzVlJkalR5OU80R0VXRk9JaGtabHJMOVpjTldlOFdoaUN0bjQ0N3JnSTFRaHRadFgKbUF4VVovbVpkc3dRZ3ZQMGVxV09HV2FyQzFiK1JCUUZvN3VGME5vNk40dlRscE5CQ3hvejNDWXZscFh3T0RZVQo0ZHBkcHNvRjZQZForOHVNaDRoVlkvMncxLzZxZ3d3ZTRFODVSa3VtQnd5UEhRR09GS2tKREYyNm5CTE0xSEdGCitCTENjcFVhdElTZ0xPOWVEbTF0aGNEdm1hc2g5SG1hSDduSisxOTVjazBDQXdFQUFhTWpNQ0V3RGdZRFZSMFAKQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUJ3QQphWk5IdmhsYTBRV3pucmVxa1BrZDFiVWJNaXQ0UjVKYlRHWWs2Y2QzN3pMQVdBNjBpbndhWjBBNEdGazdWVm9tClpicnUzL0RkaG9JNG9qY1kyNmVxWTBDYnJoaXpWMTBtbEk4US9jZHUxRUtwREZ3ckhpd05rMnJzQlZib3g4RXMKUXV5OWpnYjUxV0lGaFV5NEMwYXFTbWM0OTVHZzlwQ3h6czRjQ3VxSnRiOE95VUVVQktieHl6OWxBMWE3WlVweApCb2ZCcGJieUJSdG5mMjdtUVR5eFZjWkJ6a0hBajFPdXEwbUJpWHM0YzNZTEdiTnNlMDBNUDBHNlV3dG1zYmV2ClBDbUhEQUh6UHZiN045dk1aNGpycXVsa2FOMVMySDkwOTFwSDBEeEE4c3JVbDBKQ3VCN3AwM3VQcnhDT1NBd1QKNk9rekFXa1B4elRveXBBKzdmVT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
  group: build.openshift.io
  groupPriorityMinimum: 9900
  service:
    name: api
    namespace: openshift-apiserver
  version: v1
  versionPriority: 15
status:
  conditions:
  - lastTransitionTime: 2018-09-11T19:54:16Z
    message: all checks passed
    reason: Passed
    status: "True"
    type: Available
```

* **secret cabundle injector:**
  * Watches for secrets annotated with 'service.beta.openshift.io/inject-cabundle=true' and adds or updates a data item (key "service-ca.crt") containing the PEM-encoded CA signing bundle. Consumers of the secret can then trust service-ca.crt in their TLS client configuration, allowing connections to services that utilize service-serving certificates.
  * Note: Explicitly referencing the "service-ca.crt" key in a volumeMount will prevent a pod from starting until the secret has been injected with the CA bundle (https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod). This behavior helps ensure that pods start with the CA bundle data available.

```
$ oc create secret generic foobar --from-literal=key1=foo
secret/foobar created
$ oc get secret/foobar -o yaml
apiVersion: v1
data:
  key1: Zm9v
kind: Secret
metadata:
  creationTimestamp: "2022-12-06T12:29:55Z"
  name: foobar
  namespace: demo
  resourceVersion: "149235"
  uid: e2839b33-a588-422a-aa95-575e66014fa2
type: Opaque
$ oc annotate secret foobar service.beta.openshift.io/inject-cabundle="true"
secret/foobar annotated
$ oc get secret/foobar -o yaml
apiVersion: v1
data:
  key1: Zm9v
  service-ca.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVVENDQWptZ0F3SUJBZ0lJWjZDSi9jbHphY0F3RFFZSktvWklodmNOQVFFTEJRQXdOakUwTURJR0ExVUUKQXd3cmIzQmxibk5vYVdaMExYTmxjblpwWTJVdGMyVnlkbWx1WnkxemFXZHVaWEpBTVRZM01ETXlOemsxTVRBZQpGdzB5TWpFeU1EWXhNakF4TWpKYUZ3MHlOVEF5TURNeE1qQXhNak5hTURZeE5EQXlCZ05WQkFNTUsyOXdaVzV6CmFHbG1kQzF6WlhKMmFXTmxMWE5sY25acGJtY3RjMmxuYm1WeVFERTJOekF6TWpjNU5URXdnZ0VpTUEwR0NTcUcKU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ255Yk5qcENMbW5xY2Vjb1VvTUx0ajZyKzZGNWxGOEoybAoyV0YvQ25ZV0hBS2tnQlplbCtXejZMZkRBeFZwaGxQZEw2RU0xK1QxWjVSenFvZ0pKbVRTT2lHenNUdUhkUE1vCktEY3ZJTGpYekVaT3BLV3psQkUreWJyaW9YRlJtbTNqYzJmeDFVV0I3OHBJT1BwN3JoVXZsa0FhcDlIUmJNR28KUUw2SFlTT05WUHRzckl6V3QzRVRmNlBYeVpJbHZhcWxMa3p2ZG9HbzhYTUV0ZGJkQi9jcHIyTGJqenFCek84LwplVlhoTUJyUnFZczhRdkhZbE5pbWtSMXpqS01pV3hrbjZwYUxUSWxURTdoajVVUlRndHo2TlZ6WG0ycVROZXR4Cm5tZU16d2ErMnZNSnFOeExIdUxDWWJJQTNOTFRlcFRXZ01iWDcxaDdRK3dFbCtaSFplWFhBZ01CQUFHall6QmgKTUE0R0ExVWREd0VCL3dRRUF3SUNwREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQjBHQTFVZERnUVdCQlJRUjl1RgpBUFlJR0VjZVVTSTRJK3hKZ3lyb0l6QWZCZ05WSFNNRUdEQVdnQlJRUjl1RkFQWUlHRWNlVVNJNEkreEpneXJvCkl6QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFreWlEMUM2RldROXM3ZDA1UHhobU5xcnRtTUo3aElXQndIYysKRXlQUUthaWJvRUFpRnR4bnI4Tkh6TGVCQUQrblFlUzlGTTFrYnBFcWdMdWY2QnhtUy9kdlRKUUFWanpqWTJRdQpKc0NMZUpDTXU4dDZ2VmRxR2k0ckxubGxWc3VzY2FOamNiVmhHK0NpMS9tN2NRY2FiNUdMRk9LeXdZWWRaMUtDCmVNVUl0Nko5dHBBTzk3Z0Q1MUVPd2pnZG9WUFRkNCtMb2NVa3dNZjRGNDZlMmpSOEtxWWF5WnpVeWNwcFJyeXIKZEQveTRFVjRvYUs3a3hsWTJ1YUxyUkxxTmNab3dTek9OcEVjTkp6RWE4YzRxZ0lmWUZzWloyQ0ZWcVMrS0Z5RQp6OGVDUTFnQmdQek82dzMybUdKbFczMjJDeTA1UGVSZ1l0MTBiVFRqQ05kYVJMNmJDdz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVVENDQWptZ0F3SUJBZ0lJVmdYemZMdngwdkF3RFFZSktvWklodmNOQVFFTEJRQXdOakUwTURJR0ExVUUKQXd3cmIzQmxibk5vYVdaMExYTmxjblpwWTJVdGMyVnlkbWx1WnkxemFXZHVaWEpBTVRZM01ETXlOemsxTVRBZQpGdzB5TWpFeU1EWXhNakF3TVRsYUZ3MHlOVEF5TURNeE16QXdNakJhTURZeE5EQXlCZ05WQkFNTUsyOXdaVzV6CmFHbG1kQzF6WlhKMmFXTmxMWE5sY25acGJtY3RjMmxuYm1WeVFERTJOekF6TWpjNU5URXdnZ0VpTUEwR0NTcUcKU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRERCWnJ0VzZpRjQyeis4LzVpY0hJcStaM3BnL2FETG1ObQpPSGdyUzlnbVJhMnQ5aHg1VkZCYVVvQStCMys0ZVlLOG9YMEc5MjVUTEE5bzdyQkYyNm1DZzVzcEhUK2ozaFJ0CkZ1Z29IOHNUMWxKQzNkU3JNMVlWRW4xVGVjb21TYVVKNDJrc2M4QzFvVW9oNlQ2ODFlRVFnT0R6MGxPektWNWIKVW5nK0dhaVNxbVdWY3pmRW14MzBBcVUvdlB3bEc5Q2tGSEJSSXNmeTJHNHRIZFNhNWhjV3NYa1gzZ2F3d0M1bApPRk1LSVViN3piaklrUU5FK0FjR0ZlYkw2Nnl4RFRmQmUvRlhabXo3Mmlrc3d5cmhpWDcyTG85MmhuVmxMQUZICjUwZU9KdGNPK1FpVFZ2cTVydzJKUkIwSGJocWFuZEl6bU82UlpVSDZxUXd6REkrVlR2d1ZBZ01CQUFHall6QmgKTUE0R0ExVWREd0VCL3dRRUF3SUNwREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQjBHQTFVZERnUVdCQlIzV1lYNgpreFFIL0J4S3FBQWVNYXhqelQrcDVqQWZCZ05WSFNNRUdEQVdnQlJRUjl1RkFQWUlHRWNlVVNJNEkreEpneXJvCkl6QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFEdDFtK3phM3pBalBWYzkwV04yN2Q5Ull4N1grUjFib0E2KzgKZ1lvSFVPdlBIRi9FSnBlRFF2bFo0cnAyM243UmdNeU9FYkxMSVgxdVlvMWhMRXZuWDd2bWdvaXh5TDZVSjRPVwpFbHBFUUJBRjNVand4TFI3NFRUSHlYbW5Bcy9Gb1NEUFFzTVdVS24xZkJwWVpySGtoYlNmWWJKMFZ1Mk13TjJ6CnYyQnRadFM3YWV3d0xiWWxMWFZOQ2Z4UkN4WTRBSHZrQmVYYTRpN0swdEx3MDJINEhIL2pwdGJXQkhmTmQ5c3UKbW5rMklUU3EyT1Zwd2I4d2JSdzFqaDBxZzJtajhMbUV2MGhpeXUxRnpncW9sK2hnbkk4aTZqVUE5WGxRRkVscQo1ZXNrTk9NeUtuTFowSnBBZnFYZUxwcW9rTW8rcTFvNER5aURnWFJkKzZCdkVjRXpPZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
kind: Secret
metadata:
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
  creationTimestamp: "2022-12-06T12:29:55Z"
  name: foobar
  namespace: demo
  resourceVersion: "149677"
  uid: e2839b33-a588-422a-aa95-575e66014fa2
```

The openshift-service-ca-operator is an
[OpenShift ClusterOperator](https://github.com/openshift/enhancements/blob/master/enhancements/dev-guide/operators.md#what-is-an-openshift-clusteroperator)

The ServiceCA [Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) is defined in this repository.    
The [Custom Resource Definition](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/#customresourcedefinitions)
`servicecas.operator.openshift.io`    
can be viewed in a cluster with:

```console
$ oc get crd servicecas.operator.openshift.io -o yaml
```

Many OpenShift ClusterOperators share common build, test, deployment, and update methods.    
For information about how to build, deploy, test, update, and develop OpenShift ClusterOperators, see    
[OpenShift ClusterOperator and Operand Developer Document](https://github.com/openshift/enhancements/blob/master/enhancements/dev-guide/operators.md#how-do-i-buildupdateverifyrun-unit-tests)

This section explains how to deploy OpenShift with your version of a service-ca-operator image:        
[Testing a ClusterOperator/Operand image in a cluster](https://github.com/openshift/enhancements/blob/master/enhancements/dev-guide/operators.md#how-can-i-test-changes-to-an-openshift-operatoroperandrelease-component)
