class Input {
    static String get() {
        return "user";
    }
}

class SqlExecutor extends BaseExecutor {
    void run() {
        String userInput = Input.get();
        execute(userInput);
    }
}
