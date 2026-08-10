# runix-audit-broker build. The full binary links system Jansson (chosen for
# native duplicate-key rejection, JSON_REJECT_DUPLICATES); the core (framing,
# sink, peer, id) is JSON-library-independent and has its own sanitized test
# target that builds today. `make` (the binary) additionally needs the JSON
# layer (src/json.c, src/main.c) and libjansson-dev.

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

JSON_CFLAGS := $(shell pkg-config --cflags jansson 2>/dev/null)
JSON_LIBS   := $(shell pkg-config --libs jansson 2>/dev/null)

BIN := audit-broker
CORE := src/proto.c src/sink.c src/peer.c src/id.c
BROKER_SRC := $(CORE) src/json.c src/record.c src/broker.c src/main.c

PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/libexec
UNITDIR ?= /lib/systemd/system

.PHONY: all test test-json test-broker test-socket test-fixtures check fuzz probe asan clean install
all: $(BIN)

# One-shot client used by the activation gate: connect + send one open_intent.
probe: tools/rab-probe.c src/proto.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o rab-probe $(LDFLAGS)

check: test test-json test-broker test-socket test-fixtures

# The full broker binary (needs libjansson-dev + the JSON/main sources).
$(BIN): $(BROKER_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) $^ -o $@ $(LDFLAGS) $(JSON_LIBS)

# Core unit tests, JSON-library-independent, built with ASan/UBSan.
test: $(CORE) tests/test_core.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) -fsanitize=address,undefined -g \
	    $^ -o build-test-core
	./build-test-core

# Parser/schema tests against system Jansson, built with ASan/UBSan.
test-json: src/json.c tests/test_json.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) \
	    -fsanitize=address,undefined -g $^ -o build-test-json $(JSON_LIBS)
	./build-test-json

# Broker state-machine tests (lifecycle, reconstruction, rotation, rate) against
# system Jansson, built with ASan/UBSan.
test-broker: src/broker.c src/record.c src/json.c $(CORE) tests/test_broker.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) \
	    -fsanitize=address,undefined -g $^ -o build-test-broker $(JSON_LIBS)
	./build-test-broker

# An ASan/UBSan build of the whole broker binary, so the daemon runs under the
# sanitizer during the live socket tests.
build-broker-asan: $(BROKER_SRC)
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) \
	    -fsanitize=address,undefined -g $^ -o build-broker-asan $(JSON_LIBS)

# Socket-level tests: exec the ASan broker and drive it over AF_UNIX (slowloris,
# concurrency, disconnect durability, connection limits). Built with ASan/UBSan.
test-socket: build-broker-asan src/broker.c src/record.c src/json.c $(CORE) \
             tests/test_socket.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) \
	    -fsanitize=address,undefined -g src/broker.c src/record.c src/json.c \
	    $(CORE) tests/test_socket.c -o build-test-socket $(JSON_LIBS)
	RAB_BROKER_BIN=./build-broker-asan ./build-test-socket

# Cross-repo fixture cross-check: the broker's response builders + frame reader
# against the SAME shared corpus the runix R adapter validates (vendored under
# tests/fixtures/broker-frames/). Runs from the repo root so the fixture paths
# resolve. Built with ASan/UBSan.
test-fixtures: src/json.c src/proto.c tests/test_fixtures.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) \
	    -fsanitize=address,undefined -g $^ -o build-test-fixtures $(JSON_LIBS)
	./build-test-fixtures

# Protocol/parser fuzzing. Requires clang (libFuzzer): invoke as
# `make fuzz CC=clang`. Runs the request parser under the fuzzer + ASan/UBSan.
fuzz: fuzz/fuzz_frame.c src/json.c
	$(CC) $(CPPFLAGS) -std=c11 $(JSON_CFLAGS) \
	    -fsanitize=fuzzer,address,undefined -g $^ -o fuzz-proto $(JSON_LIBS)

clean:
	rm -f $(BIN) build-test-core build-test-json build-test-broker \
	    build-test-socket build-test-fixtures build-broker-asan fuzz-proto \
	    rab-probe src/*.o

install: $(BIN)
	install -D -m 0755 $(BIN) \
	    $(DESTDIR)$(LIBEXECDIR)/runix/audit-broker
	install -D -m 0644 systemd/runix-audit.socket \
	    $(DESTDIR)$(UNITDIR)/runix-audit.socket
	install -D -m 0644 systemd/runix-audit.service \
	    $(DESTDIR)$(UNITDIR)/runix-audit.service
