/* libFuzzer harness for the request parser + schema validator, the broker's
 * largest attack surface (everything a hostile client's frame body reaches).
 * Feeds arbitrary bytes as a frame body to rab_parse_request; the parser must
 * never crash, leak, read out of bounds, or accept malformed input. Build with
 * clang: `make fuzz` (see Makefile), run `./fuzz-proto -max_total_time=...`. */
#include "../src/json.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    rab_request req;
    const char *err = NULL;
    if (rab_parse_request((const char *) data, size, &req, &err) == 0) {
        /* a body the parser accepted: exercise the produced tree, then free */
        (void) rab_json_depth(req.record);
        rab_request_free(&req);
    }
    return 0;
}
