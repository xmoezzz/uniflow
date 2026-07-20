#include <stdlib.h>

int main(void) {
#ifdef _WIN32
    char *command = getenv("COMSPEC");
#else
    char *command = getenv("SHELL");
#endif
    return system(command);
}
