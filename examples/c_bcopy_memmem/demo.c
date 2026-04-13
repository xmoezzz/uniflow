int system(const char *cmd);
char *getenv(const char *name);
void bcopy(const void *src, void *dst, unsigned long n);
char *memmem(const void *haystack, unsigned long haystacklen, const void *needle, unsigned long needlelen);

typedef struct Node {
    struct Node *next;
    char cmd[64];
} Node;

void run(Node *head) {
    char *src = getenv("CMD");
    bcopy(src, head->next->cmd, 8);
    char *alias = memmem(head->next->cmd, 8, "A", 1);
    system(alias);
}
