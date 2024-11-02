run:
	cargo r

build:
	cargo b

benchmark:
	cargo bench

release:
	cargo b --release

docker-build:
	docker build -f docker/Dockerfile -t gtw/recrypt:local .

docker: docker-build
	docker run -p 50051:50051 --name gtw-recrypt gtw/recrypt:local

stop:
	docker stop gtw-recrypt
	docker rm gtw-recrypt

BUILD_TAG = "local"
PUSH_TAG = "internal"
docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 -f docker/Dockerfile -t us-docker.pkg.dev/gateway-protocol/services/recrypt:$(PUSH_TAG) .
	docker push us-docker.pkg.dev/gateway-protocol/services/recrypt:$(PUSH_TAG)

.PHONY: build benchmark release docker-build docker docker-push