#include <cstdlib>
int main() {
    const char *endpoint = "http://example.invalid/api";
    return std::system(endpoint);
}
