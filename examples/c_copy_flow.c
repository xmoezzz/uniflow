int main(void) {
  char *cmd = getenv("CMD");
  char buf[64];
  strcpy(buf, cmd);
  system(buf);
  return 0;
}
