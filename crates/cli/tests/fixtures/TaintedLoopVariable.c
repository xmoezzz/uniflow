char *getenv(const char *);

void process(int limit) {
    char *value = getenv("UNTRUSTED");
    while (value < limit) {
        break;
    }
}
