#include <stdint.h>
#define MAX_EDGES 65536

extern uint8_t EDGES_MAP[MAX_EDGES];
extern unsigned long EDGES_COUNT;

uint8_t EDGES_MAP[MAX_EDGES] = {0};
unsigned long EDGES_COUNT = 0;

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    uint32_t idx = 1;
    while (start < stop) {
        *start = idx;
        start++;
        idx++;
    }
    EDGES_COUNT = (unsigned long)(idx - 1);
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t idx = *guard;
    if (idx > 0 && idx < MAX_EDGES) {
        if (EDGES_MAP[idx] < 255) {
            EDGES_MAP[idx]++;
        }
    }
}
