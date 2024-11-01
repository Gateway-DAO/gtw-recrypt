build:
	cargo b

benchmark:
	cargo bench

release:
	cargo b --release

build-docker:
	docker build -f docker/Dockerfile -t gtw/recrypt:local .

.PHONY: build benchmark release