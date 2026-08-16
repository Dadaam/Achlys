#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cJSON.h"

#define ACHLYS_AFL_HARNESS_CAP 4096

/*
 * AFL++ / libFuzzer entry for vendored cJSON.
 * NUL-terminate a bounded copy, parse, delete. Always return 0.
 * This is a harness, not a performance or superiority claim.
 */

int achlys_cjson_test_one_input(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return achlys_cjson_test_one_input(data, size);
}

int achlys_cjson_test_one_input(const uint8_t *data, size_t size) {
    char buf[ACHLYS_AFL_HARNESS_CAP];
    size_t n = size;

    if (n >= sizeof(buf)) {
        n = sizeof(buf) - 1;
    }
    if (n > 0 && data != NULL) {
        memcpy(buf, data, n);
    }
    buf[n] = '\0';

    cJSON *parsed = cJSON_Parse(buf);
    if (parsed != NULL) {
        cJSON_Delete(parsed);
    }
    return 0;
}
