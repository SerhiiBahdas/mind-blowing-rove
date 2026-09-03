CC := xcrun clang
CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -O2
FRAMEWORKS := -framework CoreFoundation -framework IOKit
BUILD_DIR := build
PROBE := $(BUILD_DIR)/mindrove-usb-probe
PROBE_SOURCE := tools/mindrove-usb-probe/main.c

.PHONY: all build probe check clean

all: build

build: $(PROBE)

$(PROBE): $(PROBE_SOURCE)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(PROBE_SOURCE) $(FRAMEWORKS) -o $(PROBE)

probe: $(PROBE)
	./$(PROBE)

check: $(PROBE)
	./$(PROBE) --help >/dev/null
	./$(PROBE) --json >/dev/null || test $$? -eq 2
	sh -n bridge/linux/mindrove-router.sh
	sh -n bridge/macos/mindrove-route.sh

clean:
	rm -rf $(BUILD_DIR)
