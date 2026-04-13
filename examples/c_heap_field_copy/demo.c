typedef struct Node {
  char *cmd;
  struct Node *next;
} Node;

int main(void) {
  char *cmd = getenv("CMD");
  Node *req = malloc(sizeof(*req));
  req->next = malloc(sizeof(*req->next));
  req->next->cmd = strdup(cmd);
  system(req->next->cmd);
  return 0;
}
