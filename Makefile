.PHONY: build test test-unit test-integration emulator-up emulator-down

# Default test target: unit tests only (no external dependencies).
test: test-unit

build:
	go build -o bin/spec-graph .

test-unit:
	go vet ./...
	go test ./...

# test-integration runs the Spanner-emulator-backed tests. Starts the
# emulator via Docker, runs the integration test suite (build-tagged
# `integration`), then tears the emulator down. The tests create the
# test instance themselves (ensureEmulatorInstance), exactly as they must
# in CI, where the emulator is started bare with no out-of-band setup.
#
# REQUIREMENTS.md §9 names this discipline as a before-merge requirement
# alongside unit tests.
test-integration:
	@bash ./scripts/test-integration.sh
