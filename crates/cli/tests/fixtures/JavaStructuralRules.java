// Bundle smoke fixture: deliberately contains findings.
class JavaStructuralRules {
    boolean ready;
    int count;
    Object lock = new Object();

    void empty() {}

    void branches(boolean flag) {
        if (flag) {}
        if (flag) work(); else {}
        while (ready) {}
        synchronized (lock) {}
        try {} finally { work(); }
        if (ready = false) work();
        ;;
        if (ready); { work(); }
        switch (count) { case 1: break; }
    }

    void infinite() {
        while (true) {}
    }

    boolean compare(boolean a, boolean b, boolean c) {
        return (a == b) == c;
    }

    void work() {
        count++;
    }

    void floatingCounter() {
        for (double value = 0; value < 1; value += 0.1) work();
    }
}
