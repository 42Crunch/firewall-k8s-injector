# Kubernetes Injector for 42Crunch Micro-API Firewall

## Table of Contents

- [Overview](#overview)
- [What is it?](#what-is-it)
- [Building the Injector](#building-the-injector)
- [Injector Installation](#injector-installation)
- [Injection Labels](#injection-labels)
- [Annotations](#annotations)

## Overview

Kubernetes Injector for 42Crunch Micro-API Firewall protects REST APIs exposed by microservices deployed in Kubernetes. The Micro-API firewall enforces the Positive Security Model based on the API definition (in [OpenAPI](https://swagger.io/specification/) format). The firewall gets automatically deployed within the pods and enforces security on calls and responses with submillisecond overhead.

## What is it?

This project contains a [Kubernetes Admission Controller](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) which automatically injects a sidecar container with [42Crunch Micro-API Firewall](https://42crunch.com/micro-api-firewall-protection/) into deployments marked with a specific label.

The code dynamically creates the firewall configuration and the resulting config goes into a sidecar container which is injected into the pod. The webhook has been configured to only get triggered when pods have the `firewall-injection` label `enabled` (Please check [Injection Labels](#injection-labels) section).

## Building the Injector

If you intend to build the injector locally, please execute the following:

```shell
docker build -t 42crunch/firewall-k8s-injector:latest .
```

After that push the resulting image to a repository where you intend to install it from. In our example we are pushing the built image to [42Crunch Docker Hub](https://hub.docker.com/u/42crunch) repo:

```shell
docker push 42crunch/firewall-k8s-injector:latest
```

Override `injectorImage.repo` when installing Helm chart. You can do this by going to the `helm/xliic-injector` folder and updating the `values.yaml` file:

```yaml
13   injectorImage:
14     repo: 42crunch/firewall-k8s-injector
```

## Injector Installation

The injector is installed using a [**Helm 3**](https://helm.sh) chart, and by default installs a pre-built version of injector published as `42crunch/firewall-k8s-injector:latest`.

The chart takes a number of parameters to configure the injector:

| Parameter               | Description               | Default value                    |
| ----------------------- | ------------------------- | -------------------------------- |
| `injectorImage.repo`    | Injector image            | `42crunch/firewall-k8s-injector` |
| `injectorImage.tag`     | Injector image tag        | `latest`                         |
| `apifirewall.image`     | API Firewall image to use | `42crunch/apifirewall:latest`    |
| `apifirewall.maxCpu`    | API Firewall Max CPU      | `500m`                           |
| `apifirewall.maxMemory` | API Firewall Max Memory   | `500Mi`                          |
| `apifirewall.platform`  | API Firewall Platform     | `protection.42crunch.com:8001`   |

### Installing from Helm repository 
The Helm chart is available from our central repository. Use the following commands to get the charts:
```
helm repo add 42crunch https://repo.42crunch.com/charts
helm repo update
```

To install, you can use the following command 
```
helm upgrade --install injector 42crunch/xliic-injector --set apifirewall.platform=protection.42crunch.com:8001 --namespace injector-ns --create-namespace
```

### Installing from GitHub repository

A typical Helm install command to install the injector might look like:

    helm install injector ./helm/xliic-injector --set apifirewall.platform=protection.42crunch.com:8001 --namespace injector-ns --create-namespace

To uninstall the injector use helm uninstall command:

    helm uninstall injector --namespace injector-ns

## Injection Labels

The injector checks deployments to see if `firewall-injection: enabled` label is present . If the label is missing or has any other value, the injection is not done.

```YAML
  template:
    metadata:
      labels:
        app: pixiapp
        firewall-injection: enabled
```

## Annotations

You can control runtime configuration of the firewall using annotations. There is a number of mandatory annotations which must be provided or deployment will fail.

Annotations mostly result in environment variables being created in the firewall container. You can see how the firewall can be configured through a use of environment variables [here](https://docs.42crunch.com/latest/content/extras/api_firewall_variables.htm)

Typical annotated deployment looks like this:

```YAML
  template:
    metadata:
      labels:
        app: pixiapp
        firewall-injection: enabled
      annotations:
        xliic.com/protection-token: "apifirewall-protection-token"
        xliic.com/container-port: "8443"
        xliic.com/tls-secret-name: "ssl-secret"
        xliic.com/target-url: "http://localhost:80"
        xliic.com/server-name: pixi-api.company.com
```

### Mandatory Annotations

Firewall needs at least a `protection token` and (if not running in HTTP-only mode) a TLS keypair to run. Both of these must be created as Kubernetes Secrets before attempting to inject firewall. The secret for `protection token` MUST contain a key called `PROTECTION_TOKEN` with a value of `protection token` from 42Crunch Platform.

Create a `protection token` secret:

    kubectl create secret generic apifirewall-protection-token --from-literal=PROTECTION_TOKEN=<protection token>

Create a TLS keypair secret (assuming there is certs/ssl.key and certs/ssl.crt on a filesystem):

    kubectl create secret tls ssl-secret --key=certs/ssl.key --cert=certs/ssl.crt

Now with these secrets in place, you can label deployment with `firewall-injection: enabled` and add these annotations:

| Annotation                   | Expected value                                       | Sets environment variable       |
| ---------------------------- | ---------------------------------------------------- | ------------------------------- |
| `xliic.com/protection-token` | Name of K8s secret containing `protection token`     | PROTECTION_TOKEN                |
| `xliic.com/container-port`   | K8s Container Port for the firewall container        | LISTEN_PORT                     |
| `xliic.com/target-url`       | Target URL for firewall                              | TARGET_URL                      |
| `xliic.com/server-name`      | Firewall server name                                 | SERVER_NAME                     |
| `xliic.com/tls-secret-name`  | Name of K8s TLS secret for configuring firewalls SSL | LISTEN_SSL_CERT, LISTEN_SSL_KEY |

### Optional Annotations

| Annotation                        | Expected value                                                                       | Sets environment variable                                                         |
| --------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| `xliic.com/http-only`             | Can be set to `enabled`                                                              | LISTEN_NO_TLS                                                                     |
| `xliic.com/conf-volume`           | Name of K8s persistent volume claim with firewall configuration                      |
| `xliic.com/log-to-volume`         | Name of K8s persistent volume claim, for writing firewall logs to persistent storage |                                                                                   |
| `xliic.com/env-configmap`         | Name of K8s ConfigMap                                                                | Each key in the config map will result in respective environment variable         |
| `xliic.com/debug`                 | Can be set to `enabled`                                                              | Increases trace level to debug for firewall startup                               |
| `xliic.com/inject-secret-env-jwk` | Name of K8s Secret and Secret Key separated by `/` for example `jwk/key`             | Sets `JWK` environment variable with data read from respective K8s secret and key |

## Examples

Please see `examples/` folder for sample deployments.
