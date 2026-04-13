typedef struct DB { char *cmd; } DB;
typedef struct Request { DB *db; } Request;

int main(void) {
  char *cmd = getenv("CMD");
  Request *req = malloc(sizeof(*req));
  req->db = malloc(sizeof(*req->db));
  req->db->cmd = strdup(cmd);
  char *alias = req->db->cmd;
  system(alias);
  return 0;
}
