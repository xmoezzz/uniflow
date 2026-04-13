#include <stdlib.h>
#include <string.h>

int main(void) {
  char *cmd = getenv("CMD");
  char buf[128];
  char *alias = buf;
  memcpy(alias, cmd, 16);
  system(buf);
  return 0;
}
