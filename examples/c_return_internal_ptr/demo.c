#include <stdlib.h>
#include <string.h>

int main(void) {
    char *cmd = getenv("CMD");
    char *alias = strstr(cmd, "run");
    system(alias);
    return 0;
}
