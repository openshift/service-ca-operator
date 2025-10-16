# OpenShift Origin Utility Library

This repository contains a Go library with utility functions for interacting with OpenShift and Kubernetes clusters. It provides a convenient client for managing cluster resources, with a particular focus on simplifying end-to-end (e2e) testing.

## Goal
Avoid being able to directly pull an entire oversized origin along with the corresponding complex dependencies, as this can easily contaminating our project and cause conflicts with the new OpenShift/K8s version. And every time, GOSUMDB has to be turned off, which is not very user-friendly for CI/CD. The future might be even more troublesome. Therefore consider from origin/test/extended/util alone cut out to be a lightweight repo (such as the origin - util), multiple repo when using, go to get github.com/wangke19/origin-util@v0.x. Version is controllable.

## Prerequisites

Before using this library, you will need:

1.  **A running OpenShift Cluster**.
2.  **A `kubeconfig` file** that points to your cluster. The library will search for the config file based on the `KUBECONFIG` environment variable or in the default `~/.kube/config` location.
3.  **Cluster-admin privileges** for the user context in your `kubeconfig`, as many of the utility functions interact with cluster-level resources.

## Usage

To use this library in your Go project, you can import it as follows:

```go
import (
    "fmt"
    "context"

    "github.com/wangke19/origin-util"
    "k8s.io/kubernetes/test/e2e/framework"
)

func main() {
    // This library is designed to be used within a testing framework like Ginkgo.
    // The following is a simplified conceptual example.

    // 1. Initialize the CLI helper
    // The second argument to NewCLI is the Pod Security level.
    // For more details, refer to the implementation in `client.go`.
    cli := util.NewCLI("my-test-project", admissionapi.LevelRestricted)

    // 2. Get the cluster version
    clusterVersion, err := util.GetClusterVersion(context.Background(), cli.AdminConfig())
    if err != nil {
        panic(err)
    }

    fmt.Printf("Cluster version: %s\n", clusterVersion.Status.Desired.Version)

    // 3. Use the client to interact with the cluster
    // For example, to get a list of pods in the current project:
    pods, err := cli.KubeClient().CoreV1().Pods(cli.Namespace()).List(context.Background(), metav1.ListOptions{})
    if err != nil {
        panic(err)
    }

    fmt.Printf("Found %d pods in project %s\n", len(pods.Items), cli.Namespace())
}
```

## Key Features

*   **CLI Wrapper**: A `CLI` struct that simplifies running `oc` commands and interacting with the cluster's APIs.
*   **Client Management**: Easy creation of clients for various Kubernetes and OpenShift API groups.
*   **Project/Namespace Setup**: Helper functions to create and tear down projects/namespaces for tests.
*   **Cluster Information**: Functions to retrieve cluster version and operator status.
*   **Testing Focused**: Designed to be used within a testing framework like Ginkgo, with integration with the Kubernetes e2e test framework.

This library is primarily intended for internal OpenShift e2e testing and may not be suitable for general-purpose applications.
