#include <string.h>
#include <stdlib.h>

int main(void) {
    char buf[64];
    char *cmd = getenv("CMD");
    stpcpy(buf, cmd);
    char *alias = rawmemchr(buf, "A"[0]);
    return system(alias);
}
