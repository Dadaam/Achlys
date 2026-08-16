#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Mechanism target: crash if the first 4 bytes are 0xDEADBEEF little-endian. */

int achlys_micro_magic_u32(const uint8_t *data, size_t len) {
    if (len < 4) {
        return 0;
    }
    /* Reconstruct LE so the comparison is host-endian independent. */
    uint32_t value = (uint32_t)data[0]
        | ((uint32_t)data[1] << 8)
        | ((uint32_t)data[2] << 16)
        | ((uint32_t)data[3] << 24);
    if (value == 0xDEADBEEFu) {
        abort();
    }
    return 0;
}
