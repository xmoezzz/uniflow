#include <stdlib.h>
#include <string.h>

int main(void) {
    char buf[64];
    char *cmd = getenv("CMD");
    char *tail = stpncpy(buf, cmd, 16);
    char *save = NULL;
    char *tok = strtok_r(buf, "/", &save);
    system(tok ? tok : tail);
    return 0;
}
