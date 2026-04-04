BINARY    := gbrl
BUILD_DIR := ./bin
CMD_PKG   := ./cmd/gbrl

.PHONY: all build test bench clean run

all: build

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) $(CMD_PKG)
	go build -o $(BUILD_DIR)/gbrl-tui ./cmd/gbrl-tui
	@echo "Built $(BUILD_DIR)/$(BINARY) and $(BUILD_DIR)/gbrl-tui"

test:
	go test -race -v ./internal/...

bench:
	go test -bench=. -benchmem -count=3 ./benchmarks/

clean:
	rm -rf $(BUILD_DIR)

run: build
	sudo $(BUILD_DIR)/$(BINARY) $(ARGS)
