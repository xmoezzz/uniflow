int system(const char *cmd);
char *getenv(const char *name);
char *strcpy(char *dst, const char *src);

void run(void) {
    char buf[64];
    char *cmd = getenv("CMD");
    char *alias = strcpy(buf, cmd);
    system(alias);
}
