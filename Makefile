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
test-integration: emulator-up
	@echo "→ running integration tests against the Spanner emulator"
	@SPANNER_EMULATOR_HOST=localhost:9010 \
		go test -tags=integration -v ./... ; \
	rc=$$? ; \
	$(MAKE) emulator-down ; \
	exit $$rc

emulator-up:
	@echo "→ starting Spanner emulator (Docker)"
	@docker rm -f spec-graph-emulator 2>/dev/null || true
	@docker run -d --name spec-graph-emulator \
		-p 9010:9010 -p 9020:9020 \
		gcr.io/cloud-spanner-emulator/emulator
	@echo "→ waiting for emulator to be ready"
	@until curl -s http://localhost:9020/ > /dev/null 2>&1; do sleep 1; done

emulator-down:
	@echo "→ stopping Spanner emulator"
	@docker rm -f spec-graph-emulator 2>/dev/null || true
