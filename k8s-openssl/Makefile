DOCKER_IMAGE_NAME ?= 42crunch/k8s-openssl
DOCKER_IMAGE_TAG ?= 0.1.1

.PHONY: all
all: build inspect

.PHONY: build
build:
	docker buildx build -t $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) --platform linux/amd64,linux/arm64 --push .

.PHONY: inspect
inspect:
	docker buildx imagetools inspect $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
