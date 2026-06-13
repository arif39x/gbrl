BINARY    := gbrl-tui
BUILD_DIR := ./bin

.PHONY: all build test bench clean run

all: build

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/gbrl-tui
	@echo "Built $(BUILD_DIR)/$(BINARY)"

test:
	go test -race -v ./internal/...

clean:
	rm -rf $(BUILD_DIR)

run: build
	sudo $(BUILD_DIR)/$(BINARY) $(ARGS)
