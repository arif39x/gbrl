#!/bin/bash

# GBRL – General Binary Restractor & Logger


# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}[*] Building GBRL...${NC}"
make build

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Build failed.${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Launching Sandbox TUI...${NC}"
sudo ./bin/gbrl-tui "$@"
