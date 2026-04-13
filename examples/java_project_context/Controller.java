package demo.web;

import demo.app.*;
import java.sql.Statement;

public class Controller {
    private Statement stmt;

    public void handle(String input) {
        UserService svc = new UserService();
        String sql = svc.fetch(input);
        stmt.executeQuery(sql);
    }
}
