FROM alpine:3.16

# This makes it easy to build tagged images with different `kubectl` versions.
ARG KUBECTL_VERSION="v1.24.3"

# Set by docker automatically
ARG TARGETOS
ARG TARGETARCH

RUN apk --upgrade --no-cache add openssl && \
    wget "https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/${TARGETOS}/${TARGETARCH}/kubectl" && \
    chmod +x ./kubectl && mv ./kubectl /usr/local/bin/kubectl

WORKDIR /app
USER 1000
