typedef struct Request { char *cmd; } Request;

int main(void) {
  Request *req;
  req = malloc(sizeof(*req));
  req->cmd = getenv("CMD");
  system(req->cmd);
  return 0;
}
