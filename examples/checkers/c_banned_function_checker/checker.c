#include "uniflow_checker_v1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *copy_text(const char *text) {
    const size_t size = strlen(text) + 1;
    char *result = (char *)malloc(size);
    if (result != NULL) {
        memcpy(result, text, size);
    }
    return result;
}

static char *manifest_json_for_abi(unsigned abi_version) {
    char buffer[512];
    const int written = snprintf(
        buffer,
        sizeof(buffer),
        "{\"abi_version\":%u,\"id\":\"example.c-banned-function\"," 
        "\"name\":\"C Banned Function Checker\",\"version\":\"1.0.0\"," 
        "\"description\":\"C SDK example checker\",\"event_kinds\":[\"call\"]}",
        abi_version);
    if (written < 0 || (size_t)written >= sizeof(buffer)) {
        return NULL;
    }
    return copy_text(buffer);
}

static char *manifest_json_v1(void) {
    return manifest_json_for_abi(UNIFLOW_CHECKER_ABI_VERSION_V1);
}

static char *manifest_json_v2(void) {
    return manifest_json_for_abi(UNIFLOW_CHECKER_ABI_VERSION_V2);
}

static void *create_checker(void) {
    return malloc(1);
}

static char *on_event_json(void *instance, const char *event_json) {
    (void)instance;
    if (event_json == NULL || strstr(event_json, "\"kind\":\"call\"") == NULL ||
        (strstr(event_json, "strcpy") == NULL && strstr(event_json, "strcat") == NULL &&
         strstr(event_json, "gets") == NULL)) {
        return copy_text("{\"findings\":[]}");
    }
    /* Deliberately emit the same finding twice. The host must normalize and
       de-duplicate it by fingerprint. */
    return copy_text(
        "{\"findings\":["
        "{\"rule_id\":\"dangerous-call\",\"message\":\"C checker found a banned call\","
        "\"level\":\"warning\",\"location\":{\"uri\":\"examples/checker_demo/demo.c\","
        "\"line\":4,\"column\":5}},"
        "{\"rule_id\":\"dangerous-call\",\"message\":\"C checker found a banned call\","
        "\"level\":\"warning\",\"location\":{\"uri\":\"examples/checker_demo/demo.c\","
        "\"line\":4,\"column\":5}}]}");
}

static void destroy_checker(void *instance) {
    free(instance);
}

static void free_string(char *value) {
    free(value);
}

#if !defined(CHECKER_V1_ONLY)
static const uniflow_checker_v2 CHECKER_V2 = {
    UNIFLOW_CHECKER_ABI_VERSION_V2,
    sizeof(uniflow_checker_v2),
    UNIFLOW_CHECKER_CAPABILITY_JSON_EVENTS,
    manifest_json_v2,
    create_checker,
    on_event_json,
    destroy_checker,
    free_string,
};
#endif

static const uniflow_checker_v1 CHECKER_V1 = {
    UNIFLOW_CHECKER_ABI_VERSION_V1,
    manifest_json_v1,
    create_checker,
    on_event_json,
    destroy_checker,
    free_string,
};

#if !defined(CHECKER_V1_ONLY)
UNIFLOW_CHECKER_EXPORT const uniflow_checker_v2 *uniflow_checker_entry_v2(void) {
    return &CHECKER_V2;
}
#endif

UNIFLOW_CHECKER_EXPORT const uniflow_checker_v1 *uniflow_checker_entry_v1(void) {
    return &CHECKER_V1;
}
