struct Base {
    int base;
};

struct Derived : Base {
    int derived;
};

void release(Base *items) {
    delete[] (Derived *)items;
}
