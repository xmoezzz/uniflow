#include "uniflow_checker_v1.h"

#include <cstdlib>
#include <cstring>
#include <string>

namespace {
char *copy_text(const std::string &text) {
    auto *result = static_cast<char *>(std::malloc(text.size() + 1));
    if (result != nullptr) {
        std::memcpy(result, text.c_str(), text.size() + 1);
    }
    return result;
}

char *manifest_json_for_abi(unsigned abi_version) {
    return copy_text(
        std::string("{\"abi_version\":") + std::to_string(abi_version) +
        R"(,"id":"example.cpp-banned-function","name":"C++ Banned Function Checker","version":"1.0.0","description":"C++ SDK example checker","event_kinds":["call"]})");
}

char *manifest_json_v1() {
    return manifest_json_for_abi(UNIFLOW_CHECKER_ABI_VERSION_V1);
}

char *manifest_json_v2() {
    return manifest_json_for_abi(UNIFLOW_CHECKER_ABI_VERSION_V2);
}

void *create_checker() {
    return new (std::nothrow) unsigned char{0};
}

char *on_event_json(void *, const char *event_json) {
    const std::string event = event_json == nullptr ? "" : event_json;
    if (event.find("\"kind\":\"call\"") == std::string::npos ||
        (event.find("strcpy") == std::string::npos && event.find("strcat") == std::string::npos &&
         event.find("gets") == std::string::npos)) {
        return copy_text(R"({"findings":[]})");
    }
    return copy_text(
        R"({"findings":[{"rule_id":"dangerous-call","message":"C++ checker found a banned call","level":"warning","location":{"uri":"examples/checker_demo/demo.c","line":4,"column":5}}]})");
}

void destroy_checker(void *instance) {
    delete static_cast<unsigned char *>(instance);
}

void free_string(char *value) {
    std::free(value);
}

const uniflow_checker_v2 CHECKER_V2 = {
    UNIFLOW_CHECKER_ABI_VERSION_V2,
    sizeof(uniflow_checker_v2),
    UNIFLOW_CHECKER_CAPABILITY_JSON_EVENTS,
    manifest_json_v2,
    create_checker,
    on_event_json,
    destroy_checker,
    free_string,
};

const uniflow_checker_v1 CHECKER_V1 = {
    UNIFLOW_CHECKER_ABI_VERSION_V1,
    manifest_json_v1,
    create_checker,
    on_event_json,
    destroy_checker,
    free_string,
};
} // namespace

extern "C" UNIFLOW_CHECKER_EXPORT const uniflow_checker_v2 *uniflow_checker_entry_v2() {
    return &CHECKER_V2;
}

extern "C" UNIFLOW_CHECKER_EXPORT const uniflow_checker_v1 *uniflow_checker_entry_v1() {
    return &CHECKER_V1;
}
