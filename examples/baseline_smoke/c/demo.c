#include <stdio.h>
char *gets(char *);
int main(void) {
    char buffer[32];
    const char *endpoint = "http://example.invalid/api";
    (void)endpoint;
    gets(buffer);
    return 0;
}
