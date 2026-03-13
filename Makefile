APP := dnstap-filter
PKGS := ./...

.PHONY: help build test fmt vet tidy clean

help:
	@echo "Available targets:"
	@echo "  make build  - build binary ($(APP))"
	@echo "  make test   - run tests"
	@echo "  make fmt    - format Go files"
	@echo "  make vet    - run go vet"
	@echo "  make tidy   - tidy go modules"
	@echo "  make clean  - remove built binary"

build:
	go build -o $(APP) .

test:
	go test $(PKGS)

fmt:
	go fmt $(PKGS)

vet:
	go vet $(PKGS)

tidy:
	go mod tidy

clean:
	rm -f $(APP)
