#ifndef UNIFLOW_CHECKER_V1_H
#define UNIFLOW_CHECKER_V1_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UNIFLOW_CHECKER_ABI_VERSION_V1 1u
#define UNIFLOW_CHECKER_ABI_VERSION_V2 2u
#define UNIFLOW_CHECKER_ABI_VERSION_CURRENT UNIFLOW_CHECKER_ABI_VERSION_V2
#define UNIFLOW_CHECKER_ENTRY_SYMBOL_V1 "uniflow_checker_entry_v1"
#define UNIFLOW_CHECKER_ENTRY_SYMBOL_V2 "uniflow_checker_entry_v2"
#define UNIFLOW_CHECKER_CAPABILITY_JSON_EVENTS (UINT64_C(1) << 0)

#if defined(_WIN32)
#define UNIFLOW_CHECKER_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define UNIFLOW_CHECKER_EXPORT __attribute__((visibility("default")))
#else
#define UNIFLOW_CHECKER_EXPORT
#endif

typedef char *(*uniflow_checker_manifest_json_fn)(void);
typedef void *(*uniflow_checker_create_fn)(void);
typedef char *(*uniflow_checker_on_event_json_fn)(void *instance, const char *event_json);
typedef void (*uniflow_checker_destroy_fn)(void *instance);
typedef void (*uniflow_checker_free_string_fn)(char *value);

typedef struct uniflow_checker_v1 {
    uint32_t abi_version;
    uniflow_checker_manifest_json_fn manifest_json;
    uniflow_checker_create_fn create;
    uniflow_checker_on_event_json_fn on_event_json;
    uniflow_checker_destroy_fn destroy;
    uniflow_checker_free_string_fn free_string;
} uniflow_checker_v1;

typedef struct uniflow_checker_v2 {
    uint32_t abi_version;
    uint64_t struct_size;
    uint64_t capabilities;
    uniflow_checker_manifest_json_fn manifest_json;
    uniflow_checker_create_fn create;
    uniflow_checker_on_event_json_fn on_event_json;
    uniflow_checker_destroy_fn destroy;
    uniflow_checker_free_string_fn free_string;
} uniflow_checker_v2;

typedef const uniflow_checker_v1 *(*uniflow_checker_entry_v1_fn)(void);
typedef const uniflow_checker_v2 *(*uniflow_checker_entry_v2_fn)(void);

/* New checkers should export v2. Exporting v1 as well keeps compatibility with
 * UniFlow 0.x hosts. */
UNIFLOW_CHECKER_EXPORT const uniflow_checker_v2 *uniflow_checker_entry_v2(void);
UNIFLOW_CHECKER_EXPORT const uniflow_checker_v1 *uniflow_checker_entry_v1(void);

#ifdef __cplusplus
}
#endif

#endif
