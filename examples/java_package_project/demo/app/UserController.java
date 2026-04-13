package demo.app;

public class UserController {
    private UserService service;

    public void handle(String q) {
        service.execute(q);
    }
}
