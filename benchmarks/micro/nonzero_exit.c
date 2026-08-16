#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Mechanism target: return 1 if input starts with "NOK!". No abort.
 * Nonzero exit is not a crash (Master Plan §20.1). */

int achlys_micro_nonzero_exit(const uint8_t *data, size_t len) {
    if (len >= 4 && memcmp(data, "NOK!", 4) == 0) {
        return 1;
    }
    return 0;
}
