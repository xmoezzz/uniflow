#include <stdlib.h>

typedef struct Request {
  char *cmd;
} Request;

int main(void) {
  Request *req = (Request *)malloc(sizeof(Request));
  req->cmd = getenv("CMD");
  char *alias = req->cmd;
  char **pp = &alias;
  system(*pp);
  return 0;
}
