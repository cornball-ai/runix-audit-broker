# runix-audit-broker build. The full binary links system json-c; the core
# (framing, sink, peer) is json-c-independent and has its own sanitized test
# target that builds today. `make` (the binary) additionally needs the JSON
# layer (src/json.c, src/main.c) and libjson-c-dev.

CC ?= gcc

# Debian hardening flags when building on a Debian/Ubuntu toolchain.
DPKG_CFLAGS  := $(shell dpkg-buildflags --get CFLAGS 2>/dev/null)
DPKG_CPPFLAGS := $(shell dpkg-buildflags --get CPPFLAGS 2>/dev/null)
DPKG_LDFLAGS := $(shell dpkg-buildflags --get LDFLAGS 2>/dev/null)

WARN := -Wall -Wextra -Wpedantic -Wshadow -Wformat=2
CPPFLAGS := -D_GNU_SOURCE $(DPKG_CPPFLAGS)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 $(WARN) $(DPKG_CFLAGS)
LDFLAGS += $(DPKG_LDFLAGS)

JSONC_CFLAGS := $(shell pkg-config --cflags json-c 2>/dev/null)
JSONC_LIBS   := $(shell pkg-config --libs json-c 2>/dev/null)

BIN := audit-broker
CORE := src/proto.c src/sink.c src/peer.c
BROKER_SRC := $(CORE) src/id.c src/json.c src/main.c

PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/libexec
UNITDIR ?= /lib/systemd/system

.PHONY: all test asan clean install
all: $(BIN)

# The full broker binary (needs libjson-c-dev + the JSON/main sources).
$(BIN): $(BROKER_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSONC_CFLAGS) $^ -o $@ $(LDFLAGS) $(JSONC_LIBS)

# Core unit tests, json-c-independent, built with ASan/UBSan.
test: $(CORE) tests/test_core.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) -fsanitize=address,undefined -g \
	    $^ -o build-test-core
	./build-test-core

clean:
	rm -f $(BIN) build-test-core src/*.o

install: $(BIN)
	install -D -m 0755 $(BIN) \
	    $(DESTDIR)$(LIBEXECDIR)/runix/audit-broker
	install -D -m 0644 systemd/runix-audit.socket \
	    $(DESTDIR)$(UNITDIR)/runix-audit.socket
	install -D -m 0644 systemd/runix-audit.service \
	    $(DESTDIR)$(UNITDIR)/runix-audit.service
