void check(void) {
    char *bytes = 0;
    int *bad_cast = (int *)bytes;
    int words[4];
    char *narrow = (char *)words;
    char *misaligned = narrow + 1;
}
