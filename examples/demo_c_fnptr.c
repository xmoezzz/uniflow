#include <stdlib.h>

int run_command(void) {
    char *cmd = getenv("CMD");
    int (*runner)(const char *) = system;
    return runner(cmd);
}
