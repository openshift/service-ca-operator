// Code generated for package v4_00_assets by go-bindata DO NOT EDIT. (@generated)
// sources:
// bindata/v4.0.0/controller/clusterrole.yaml
// bindata/v4.0.0/controller/clusterrolebinding.yaml
// bindata/v4.0.0/controller/deployment.yaml
// bindata/v4.0.0/controller/ns.yaml
// bindata/v4.0.0/controller/role.yaml
// bindata/v4.0.0/controller/rolebinding.yaml
// bindata/v4.0.0/controller/sa.yaml
// bindata/v4.0.0/controller/signing-cabundle.yaml
// bindata/v4.0.0/controller/signing-secret.yaml
package v4_00_assets

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _v400ControllerClusterroleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:openshift:controller:service-ca
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
- apiGroups:
  - ""
  resources:
  - services
  verbs:
  - get
  - list
  - watch
  - update
  - patch
- apiGroups:
  - apps
  resources:
  - statefulsets
  verbs:
  - get
  - list
  - watch
  - update
  - patch
- apiGroups:
  - admissionregistration.k8s.io
  resources:
  - mutatingwebhookconfigurations
  - validatingwebhookconfigurations
  verbs:
  - get
  - list
  - watch
  - update
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - customresourcedefinitions
  verbs:
  - get
  - list
  - watch
  - update
- apiGroups:
  - apiregistration.k8s.io
  resources:
  - apiservices
  verbs:
  - get
  - list
  - watch
  - update
  - patch
- apiGroups:
  - ""
  resources:
  - configmaps
  verbs:
  - get
  - list
  - watch
  - update
`)

func v400ControllerClusterroleYamlBytes() ([]byte, error) {
	return _v400ControllerClusterroleYaml, nil
}

func v400ControllerClusterroleYaml() (*asset, error) {
	bytes, err := v400ControllerClusterroleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.0.0/controller/clusterrole.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v400ControllerClusterrolebindingYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:openshift:controller:service-ca
roleRef:
  kind: ClusterRole
  name: system:openshift:controller:service-ca
subjects:
- kind: ServiceAccount
  namespace: openshift-service-ca
  name: service-ca
`)

func v400ControllerClusterrolebindingYamlBytes() ([]byte, error) {
	return _v400ControllerClusterrolebindingYaml, nil
}

func v400ControllerClusterrolebindingYaml() (*asset, error) {
	bytes, err := v400ControllerClusterrolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.0.0/controller/clusterrolebinding.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v400ControllerDeploymentYaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: openshift-service-ca
  name: service-ca
  labels:
    app: service-ca
    service-ca: "true"
spec:
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: service-ca
      service-ca: "true"
  template:
    metadata:
      name: service-ca
      labels:
        app: service-ca
        service-ca: "true"
    spec:
      serviceAccountName: service-ca
      containers:
      - name: service-ca-controller
        image: ${IMAGE}
        imagePullPolicy: IfNotPresent
        command: ["service-ca-operator", "controller"]
        ports:
        - containerPort: 8443
        securityContext:
          runAsNonRoot: true
        resources:
          requests:
            memory: 120Mi
            cpu: 10m
        volumeMounts:
        - mountPath: /var/run/secrets/signing-key
          name: signing-key
        - mountPath: /var/run/configmaps/signing-cabundle
          name: signing-cabundle
      volumes:
      - name: signing-key
        secret:
          secretName: signing-key
      - name: signing-cabundle
        configMap:
          name: signing-cabundle
      nodeSelector:
        node-role.kubernetes.io/master: ""
      priorityClassName: "system-cluster-critical"
      tolerations:
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: "NoSchedule"
      - key: "node.kubernetes.io/unreachable"
        operator: "Exists"
        effect: "NoExecute"
        tolerationSeconds: 120
      - key: "node.kubernetes.io/not-ready"
        operator: "Exists"
        effect: "NoExecute"
        tolerationSeconds: 120
`)

func v400ControllerDeploymentYamlBytes() ([]byte, error) {
	return _v400ControllerDeploymentYaml, nil
}

func v400ControllerDeploymentYaml() (*asset, error) {
	bytes, err := v400ControllerDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.0.0/controller/deployment.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v400ControllerNsYaml = []byte(`apiVersion: v1
kind: Namespace
metadata:
  name: openshift-service-ca
  annotations:
    openshift.io/node-selector: ""
  labels:
    openshift.io/run-level-: "" # remove the label on upgrades`)

func v400ControllerNsYamlBytes() ([]byte, error) {
	return _v400ControllerNsYaml, nil
}

func v400ControllerNsYaml() (*asset, error) {
	bytes, err := v400ControllerNsYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.0.0/controller/ns.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v400ControllerRoleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: system:openshift:controller:service-ca
  namespace: openshift-service-ca
rules:
- apiGroups:
  - security.openshift.io
  resources:
  - securitycontextconstraints
  resourceNames:
  - restricted
  verbs:
  - use
- apiGroups:
  - ""
  resources:
  - events
  verbs:
  - create
- apiGroups:
  - ""
  resources:
  - configmaps
  verbs:
  - get
  - list
  - watch
  - update
  - create
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - "apps"
  resources:
  - replicasets
  - deployments
  verbs:
  - get
  - list
  - watch
`)

func v400ControllerRoleYamlBytes() ([]byte, error) {
	return _v400ControllerRoleYaml, nil
}

func v400ControllerRoleYaml() (*asset, error) {
	bytes, err := v400ControllerRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.0.0/controller/role.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v400ControllerRolebindingYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: system:openshift:controller:service-ca
  namespace: openshift-service-ca
roleRef:
  kind: Role
  name: system:openshift:controller:service-ca
subjects:
- kind: ServiceAccount
  namespace: openshift-service-ca
  name: service-ca
`)

func v400ControllerRolebindingYamlBytes() ([]byte, error) {
	return _v400ControllerRolebindingYaml, nil
}

func v400ControllerRolebindingYaml() (*asset, error) {
	bytes, err := v400ControllerRolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.0.0/controller/rolebinding.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v400ControllerSaYaml = []byte(`apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: openshift-service-ca
  name: service-ca
`)

func v400ControllerSaYamlBytes() ([]byte, error) {
	return _v400ControllerSaYaml, nil
}

func v400ControllerSaYaml() (*asset, error) {
	bytes, err := v400ControllerSaYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.0.0/controller/sa.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v400ControllerSigningCabundleYaml = []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  namespace: openshift-service-ca
  name: signing-cabundle
data:
  ca-bundle.crt:
`)

func v400ControllerSigningCabundleYamlBytes() ([]byte, error) {
	return _v400ControllerSigningCabundleYaml, nil
}

func v400ControllerSigningCabundleYaml() (*asset, error) {
	bytes, err := v400ControllerSigningCabundleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.0.0/controller/signing-cabundle.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v400ControllerSigningSecretYaml = []byte(`apiVersion: v1
kind: Secret
metadata:
  namespace: openshift-service-ca
  name: signing-key
type: kubernetes.io/tls
data:
  tls.crt:
  tls.key:
`)

func v400ControllerSigningSecretYamlBytes() ([]byte, error) {
	return _v400ControllerSigningSecretYaml, nil
}

func v400ControllerSigningSecretYaml() (*asset, error) {
	bytes, err := v400ControllerSigningSecretYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.0.0/controller/signing-secret.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"v4.0.0/controller/clusterrole.yaml":        v400ControllerClusterroleYaml,
	"v4.0.0/controller/clusterrolebinding.yaml": v400ControllerClusterrolebindingYaml,
	"v4.0.0/controller/deployment.yaml":         v400ControllerDeploymentYaml,
	"v4.0.0/controller/ns.yaml":                 v400ControllerNsYaml,
	"v4.0.0/controller/role.yaml":               v400ControllerRoleYaml,
	"v4.0.0/controller/rolebinding.yaml":        v400ControllerRolebindingYaml,
	"v4.0.0/controller/sa.yaml":                 v400ControllerSaYaml,
	"v4.0.0/controller/signing-cabundle.yaml":   v400ControllerSigningCabundleYaml,
	"v4.0.0/controller/signing-secret.yaml":     v400ControllerSigningSecretYaml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"v4.0.0": {nil, map[string]*bintree{
		"controller": {nil, map[string]*bintree{
			"clusterrole.yaml":        {v400ControllerClusterroleYaml, map[string]*bintree{}},
			"clusterrolebinding.yaml": {v400ControllerClusterrolebindingYaml, map[string]*bintree{}},
			"deployment.yaml":         {v400ControllerDeploymentYaml, map[string]*bintree{}},
			"ns.yaml":                 {v400ControllerNsYaml, map[string]*bintree{}},
			"role.yaml":               {v400ControllerRoleYaml, map[string]*bintree{}},
			"rolebinding.yaml":        {v400ControllerRolebindingYaml, map[string]*bintree{}},
			"sa.yaml":                 {v400ControllerSaYaml, map[string]*bintree{}},
			"signing-cabundle.yaml":   {v400ControllerSigningCabundleYaml, map[string]*bintree{}},
			"signing-secret.yaml":     {v400ControllerSigningSecretYaml, map[string]*bintree{}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
