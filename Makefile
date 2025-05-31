MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DELETE_ON_ERROR:
.SUFFIXES:

BINDIR := _bin

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

DASHBOARD_VERSION=0.1.0

GOLIST := $(shell ./hack/golist.sh) go.mod go.sum

.PHONY: build
build: $(BINDIR)/cert-manager-security-dashboard

.PHONY: build-all
build-all: $(BINDIR)/cert-manager-security-dashboard $(BINDIR)/cert-manager-security-dashboard-linux-amd64 $(BINDIR)/cert-manager-security-dashboard-linux-arm64

$(BINDIR)/cert-manager-security-dashboard: $(GOLIST) | $(BINDIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags '-extldflags "-static"' -o $@ main.go

$(BINDIR)/cert-manager-security-dashboard-linux-amd64: $(GOLIST) | $(BINDIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-extldflags "-static"' -o $@ main.go

$(BINDIR)/cert-manager-security-dashboard-linux-arm64: $(GOLIST) | $(BINDIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '-extldflags "-static"' -o $@ main.go

$(BINDIR):
	@mkdir -p $@

