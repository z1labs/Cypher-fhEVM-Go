.PHONY: build
build: build-tfhe-rs-capi
	cd fhevm && go build .

.PHONY: test
test: build-tfhe-rs-capi
	cd fhevm && go clean -cache && TFHE_EXECUTOR_CONTRACT_ADDRESS=0x047aF4f7F615F795baB5D367a7a1050D29B80690 go test -v ./...

.PHONY: build-tfhe-rs-capi
build-tfhe-rs-capi:
	cd tfhe-rs && RUSTFLAGS="" make build_c_api_experimental_deterministic_fft \
	&& cd target/release && rm -f *.dylib *.dll *.so

.PHONY: clean
clean:
	cd tfhe-rs && cargo clean
