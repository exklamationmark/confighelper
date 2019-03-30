test:
	GO111MODULE=on go test -mod=vendor -cover ./...
.PHONY: test

build:
	GO111MODULE=on go build -mod=vendor ./...
.PHONY: build
