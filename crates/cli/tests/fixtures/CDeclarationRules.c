extern int initialized = 1;
void unnamed(int);
struct { int member; } anonymous;
struct Outer { union Value *value; };
int array[] = {1, 2};
void invalid_void(void) { return 1; }
int missing_return(void) { work(); }
int empty_return(void) { return; }
void empty_parameters() { extern int local; }
