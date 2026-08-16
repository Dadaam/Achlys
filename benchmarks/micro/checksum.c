#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * Mechanism target: first byte is XOR of the remainder.
 * Invalid checksum returns 0 (no crash). Valid checksum plus data[1] == 0x41 aborts.
 */

int achlys_micro_checksum(const uint8_t *data, size_t len) {
    if (len < 2) {
        return 0;
    }

    uint8_t xor_sum = 0;
    for (size_t i = 1; i < len; i++) {
        xor_sum ^= data[i];
    }
    if (data[0] != xor_sum) {
        return 0;
    }
    if (data[1] == 0x41) {
        abort();
    }
    return 0;
}
