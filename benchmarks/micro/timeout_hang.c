#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Mechanism target: hang if input starts with "HANG". Not a performance claim. */

int achlys_micro_timeout_hang(const uint8_t *data, size_t len) {
    if (len >= 4 && memcmp(data, "HANG", 4) == 0) {
        /* volatile so -O3 cannot delete the empty loop. */
        volatile int keep = 1;
        while (keep) {
        }
    }
    return 0;
}
