char *source();
char *sanitize(char *x);
void sink(char *x);

void handle() {
    char *query = source();
    char *safe = sanitize(query);
    sink(safe);
}
