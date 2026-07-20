char *getenv(const char *name);
int system(const char *command);

int main(void) {
    char *cmd = getenv("CMD");
    return system(cmd);
}
