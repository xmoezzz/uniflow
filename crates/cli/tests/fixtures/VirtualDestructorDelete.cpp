struct Base { ~Base() {} };
struct Derived : Base { ~Derived() {} };
struct VirtualBase { virtual ~VirtualBase() {} };
struct VirtualDerived : VirtualBase { ~VirtualDerived() {} };

void run() {
    Base *bad = new Derived;
    delete bad;
    VirtualBase *safe = new VirtualDerived;
    delete safe;
}
