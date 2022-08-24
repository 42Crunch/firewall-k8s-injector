DOCKER_IMAGE_NAME ?= rainchei/k8s-openssl
DOCKER_IMAGE_TAG ?= latest
KUBECTL_VERSION ?= v1.24.3

.PHONY: all
all: build inspect

.PHONY: build
build:
	docker buildx build -t $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) --build-arg KUBECTL_VERSION=$(KUBECTL_VERSION) --platform linux/amd64,linux/arm64 --push .

.PHONY: inspect
inspect:
	docker buildx imagetools inspect $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
