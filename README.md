# operator
The RHTAS(Red Hat Trusted Artifact Signer) operator allows for the deployment of a production ready version of the SigStore project.

## Description
Red Hat Trusted Artifact Signer enhances software supply chain security by simplifying cryptographic signing and verifying of software artifacts, such as container images, binaries and documents. Trusted Artifact Signer provides a production ready deployment of the Sigstore project within an enterprise. Enterprises adopting it can meet signing-related criteria for achieving Supply Chain Levels for Software Artifacts (SLSA) compliance and have greater confidence in the security and trustworthiness of their software supply chains.

## Getting Started
You’ll need a Kubernetes cluster to run against. You can use an OpenShift Cluster or a Kubernetes cluster to install this operator.

### Running on the cluster
1. Build and push your image to the location specified by `IMG`:

```sh
make docker-build docker-push IMG=<some-registry>/operator:tag
```

2. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/operator:tag
```

3. Once the controller has been deployed modify the sample deployment located at `config/samples/rhtas_v1alpha1_securesign.yaml` then deploy.
NOTE: You will need an OIDC provider. This can be Amazon or Keycloak for example.

```sh
kubectl apply -f config/samples/rhtas_v1alpha1_securesign.yaml
```

4. The components have now been deployed to the Kubernetes cluster and available to be used with Cosign and Tekton chains to sign artifacts.

### Uninstall CRDs
To delete the CRDs from the cluster:

```sh
make uninstall
```

### Undeploy controller
UnDeploy the controller from the cluster:

```sh
make undeploy
```

### Local Development
#### Install the CRDs into the cluster:
```
make install
````

Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):
```
make run
```
NOTE: You can also run this in one step by running: make install run

#### Port-forward service(s)
After installation of your resource(s), you will need to allow the locally running operator to the internal service(s).
This workaround is needed because the trillian server use insecure RPC protocol for communication with others. 
Currently, it is not possible to route insecure GRPC outside the cluster so the local deployment rely on port-forward.

##### Procedure
Install your CR and wait until the operator log prints
```
Operator is running on localhost. You need to port-forward services.
Execute `oc port-forward service/trillian-logserver 8091 8091` in your namespace to continue.
```
Then execute the command as is written `oc port-forward service/trillian-logserver 8091 8091`
