GO    := go
pkgs   = $(shell $(GO) list ./... | grep -v /vendor/)

PREFIX              ?= $(shell pwd)
DOCKER_IMAGE_NAME   ?= sensu-go_exporter
DOCKER_IMAGE_TAG	?= $(shell cat VERSION)

all: style format vet build

style:
	@echo ">> checking code style"
	@! gofmt -d $(shell find . -path ./vendor -prune -o -name '*.go' -print) | grep '^'

test:
	@echo ">> running tests"
	@$(GO) test -short -race $(pkgs)

format:
	@echo ">> formatting code"
	@$(GO) fmt $(pkgs)

vet:
	@echo ">> vetting code"
	@$(GO) vet $(pkgs)

build:
	@echo ">> building binaries"
	@$(GO) build

docker:
	@echo ">> building docker image"
	@docker build --no-cache -t "meni2029/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)" .

push:
	@echo ">> pushing docker image"
	@docker push "meni2029/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)"

.PHONY: all style test format vet build docker push