struct Base {
protected:
    int inherited;
    void base_method();
};

struct Item : Base {
    int own;
    Item() try : own(0) { } catch (...) { own = 1; }
    ~Item() try { } catch (...) { this->base_method(); }
};
