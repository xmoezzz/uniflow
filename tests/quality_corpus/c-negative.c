#include <stdio.h>
int main(void) { char b[16]; const char *u = "https://example.invalid"; (void)u; return fgets(b, sizeof(b), stdin) == 0; }
