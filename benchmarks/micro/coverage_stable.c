#include <stddef.h>
#include <stdint.h>

/*
 * Mechanism target: first bytes select independent branches so a
 * coverage map is deterministic. Never crashes.
 * Volatile stores keep the edges under -O0 (Master Plan §20.1).
 */

static volatile uint8_t achlys_edge_a;
static volatile uint8_t achlys_edge_b;
static volatile uint8_t achlys_edge_c;

int achlys_micro_coverage_stable(const uint8_t *data, size_t len) {
    if (len >= 1 && data[0] == 'A') {
        achlys_edge_a = 1;
    }
    if (len >= 2 && data[1] == 'B') {
        achlys_edge_b = 1;
    }
    if (len >= 3 && data[2] == 'C') {
        achlys_edge_c = 1;
    }
    return 0;
}
