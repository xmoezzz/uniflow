#include <string.h>
#include <stdlib.h>

int main(void) {
    char buf[64];
    char *cmd = getenv("CMD");
    char *alias = mempcpy(buf, cmd, 4);
    return system(alias);
}
