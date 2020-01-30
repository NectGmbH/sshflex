TAG=v0.0.2
IMAGE=kavatech/sshflex:$(TAG)

export GOOS=linux

all: build docker-build

build:
	go build

docker-build:
	docker build -t $(IMAGE) .

docker-push:
	docker push $(IMAGE)
