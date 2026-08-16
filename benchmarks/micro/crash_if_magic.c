#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Mechanism target: crash if input starts with "BUG!". For later in-process linking. */

int parse(const uint8_t *data, size_t size) {
    if (size >= 4 && memcmp(data, "BUG!", 4) == 0) {
        abort();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return parse(data, size);
}
