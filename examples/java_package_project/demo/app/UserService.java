package demo.app;

import java.sql.Statement;

public class UserService {
    private Statement stmt;

    public void execute(String q) {
        stmt.executeQuery(q);
    }
}
