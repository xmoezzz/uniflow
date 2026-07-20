#include "uniflow_checker_v1.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define UNIFLOW_FIXTURE_UNUSED __attribute__((unused))
#else
#define UNIFLOW_FIXTURE_UNUSED
#endif

static UNIFLOW_FIXTURE_UNUSED char *copy_text(const char *text) {
    const size_t size = strlen(text) + 1;
    char *result = (char *)malloc(size);
    if (result != NULL) {
        memcpy(result, text, size);
    }
    return result;
}

static UNIFLOW_FIXTURE_UNUSED char *manifest_json(void) {
#if defined(FIXTURE_INVALID_MANIFEST)
    return copy_text("{");
#elif defined(FIXTURE_WRONG_MANIFEST_ABI)
    return copy_text("{\"abi_version\":1,\"id\":\"fixture.wrong-manifest-abi\",\"name\":\"Fixture\",\"version\":\"1\"}");
#elif defined(FIXTURE_EMPTY_ID)
    return copy_text("{\"abi_version\":2,\"id\":\"\",\"name\":\"Fixture\",\"version\":\"1\"}");
#elif defined(FIXTURE_DUPLICATE_ID)
    return copy_text("{\"abi_version\":2,\"id\":\"example.c-banned-function\",\"name\":\"Duplicate\",\"version\":\"1\",\"event_kinds\":[\"call\"]}");
#else
    return copy_text("{\"abi_version\":2,\"id\":\"fixture.checker\",\"name\":\"Fixture\",\"version\":\"1\",\"event_kinds\":[\"call\"]}");
#endif
}

static UNIFLOW_FIXTURE_UNUSED void *create_checker(void) {
    return malloc(1);
}

static UNIFLOW_FIXTURE_UNUSED char *on_event_json(void *instance, const char *event_json) {
    (void)instance;
    (void)event_json;
#if defined(FIXTURE_INVALID_RESPONSE)
    return copy_text("{");
#elif defined(FIXTURE_ERROR_RESPONSE)
    return copy_text("{\"findings\":[],\"error\":\"fixture failure\"}");
#elif defined(FIXTURE_INVALID_FINDING)
    return copy_text("{\"findings\":[{\"rule_id\":\"\",\"message\":\"bad\",\"level\":\"warning\",\"location\":{\"uri\":\"\",\"line\":0,\"column\":0}}]}");
#elif defined(FIXTURE_HANG)
    for (;;) {
        volatile uint64_t spin = 0;
        spin++;
    }
    return NULL;
#elif defined(FIXTURE_CRASH)
    *((volatile int *)0) = 1;
    return NULL;
#else
    return copy_text("{\"findings\":[]}");
#endif
}

static UNIFLOW_FIXTURE_UNUSED void destroy_checker(void *instance) {
    free(instance);
}

static UNIFLOW_FIXTURE_UNUSED void free_string(char *value) {
    free(value);
}

static const uniflow_checker_v2 CHECKER_V2 UNIFLOW_FIXTURE_UNUSED = {
#if defined(FIXTURE_WRONG_ABI)
    999u,
#else
    UNIFLOW_CHECKER_ABI_VERSION_V2,
#endif
#if defined(FIXTURE_TRUNCATED_TABLE)
    1u,
#else
    sizeof(uniflow_checker_v2),
#endif
#if defined(FIXTURE_NO_CAPABILITY)
    0u,
#else
    UNIFLOW_CHECKER_CAPABILITY_JSON_EVENTS,
#endif
#if defined(FIXTURE_NULL_CALLBACK)
    NULL,
#else
    manifest_json,
#endif
    create_checker,
    on_event_json,
    destroy_checker,
    free_string,
};

UNIFLOW_CHECKER_EXPORT const uniflow_checker_v2 *uniflow_checker_entry_v2(void) {
#if defined(FIXTURE_NULL_TABLE)
    return NULL;
#else
    return &CHECKER_V2;
#endif
}
