struct Base {
    virtual void on_construct();
};

struct Derived : Base {
    Derived() { on_construct(); }
};
