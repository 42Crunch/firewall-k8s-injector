DOCKER_IMAGE_NAME ?= rainchei/k8s-openssl
DOCKER_IMAGE_TAG ?= latest
KUBECTL_VERSION ?= v1.24.3

.PHONY: build
build:
	docker build -t $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) .
