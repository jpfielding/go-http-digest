NAME   := http-digest
TAG    := $$(git log -1 --pretty=%h)
IMG    := ${NAME}:${TAG}
LATEST := ${NAME}:latest

# the Jenkinsfile target 'make ci-build'
ci-build:
	@docker build -t ${IMG} .
	@docker tag ${IMG} ${LATEST}

all: restore-deps test build
	
test:
	go test -v ./pkg/*

vet:
	go vet ./cmd/.. ./pkg/..

clean:
	rm -rf bin *.test

restore-deps:
	go mod tidy	

build:
	CGO_ENABLED=0 go build -o bin/http-digest cmd/**.go

