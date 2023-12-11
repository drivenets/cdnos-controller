# CDNOS Controller

A controller for cdnos pod on Kubernetes Network Simulator (kne).

## Useful Links

*   [Confluence Page](https://drivenets.atlassian.net/wiki/spaces/DV/pages/4193944113/Google+Testing+Framework)

*   [KNE Project](https://drivenets.atlassian.net/wiki/spaces/DV/pages/4193944113/Google+Testing+Framework)

## Getting Started

### Prerequisites

*   go version v1.20.0+

*   docker version 17.03+.

*   kubectl version v1.11.3+.

*   Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster

**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=registry.dev.drivenets.net/devops/cdnos-controller:0.1
```

**NOTE:** This image ought to be published in the personal registry you specified. And it is required to have access to pull the image from the working environment. Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=registry.dev.drivenets.net/devops/cdnos-controller:0.1
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin privileges or be logged in as admin.

**Create instances of your solution** You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

> **NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall

**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

##
