#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Mechanism target: crash if input starts with "BUG!". Not a performance claim. */

int achlys_micro_crash_if_magic(const uint8_t *data, size_t len) {
    if (len >= 4 && memcmp(data, "BUG!", 4) == 0) {
        abort();
    }
    return 0;
}

int parse(const uint8_t *data, size_t size) {
    return achlys_micro_crash_if_magic(data, size);
}

#ifndef ACHLYS_NO_LIBFUZZER_ENTRY
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return parse(data, size);
}
#endif
