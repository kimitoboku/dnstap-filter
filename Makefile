APP := dnstap-filter
PKGS := ./...
PREFIX := /usr/local
COVERAGE_DIR := coverage

.PHONY: help build test test-coverage install uninstall fmt vet tidy clean

help:
	@echo "Available targets:"
	@echo "  make build          - build binary ($(APP))"
	@echo "  make test           - run tests"
	@echo "  make test-coverage  - run tests with coverage report"
	@echo "  make install        - install binary to $(PREFIX)/bin"
	@echo "  make uninstall      - remove binary from $(PREFIX)/bin"
	@echo "  make fmt            - format Go files"
	@echo "  make vet            - run go vet"
	@echo "  make tidy           - tidy go modules"
	@echo "  make clean          - remove built binary and coverage files"

build:
	go build -o $(APP) ./cmd/$(APP)

test:
	go test $(PKGS)

test-coverage:
	@mkdir -p $(COVERAGE_DIR)
	go test -coverprofile=$(COVERAGE_DIR)/coverage.out $(PKGS)
	go tool cover -func=$(COVERAGE_DIR)/coverage.out
	go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage report: $(COVERAGE_DIR)/coverage.html"

install: build
	install -d $(PREFIX)/bin
	install -m 755 $(APP) $(PREFIX)/bin/$(APP)

uninstall:
	rm -f $(PREFIX)/bin/$(APP)

fmt:
	go fmt $(PKGS)

vet:
	go vet $(PKGS)

tidy:
	go mod tidy

clean:
	rm -f $(APP)
	rm -rf $(COVERAGE_DIR)
