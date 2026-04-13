package demo.web;

import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import static demo.util.SqlUtil.escape;

public class Controller {
    private Statement stmt;

    public void handle(HttpServletRequest req) {
        String sql = req.getParameter("q");
        stmt.executeQuery(escape(sql));
    }
}
