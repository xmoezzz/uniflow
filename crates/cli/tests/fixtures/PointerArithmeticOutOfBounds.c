void f(void) {
    int values[3];
    int *bad = values + 3;
    int *safe = values + 2;
}
