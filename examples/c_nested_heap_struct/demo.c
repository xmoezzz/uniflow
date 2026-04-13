typedef struct DB {
  char *cmd;
} DB;

typedef struct Request {
  DB *db;
} Request;

int main(void) {
  Request *req = (Request *)malloc(sizeof(Request));
  req->db = (DB *)malloc(sizeof(DB));
  req->db->cmd = getenv("CMD");
  char *alias = req->db->cmd;
  char **pp = &alias;
  system(*pp);
  return 0;
}
