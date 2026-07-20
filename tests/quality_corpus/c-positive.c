char *gets(char *);
int main(void) { char b[16]; const char *u = "http://example.invalid"; (void)u; gets(b); return 0; }
