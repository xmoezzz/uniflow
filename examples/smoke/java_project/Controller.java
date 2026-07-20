import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;

class Controller {
    void handle(HttpServletRequest req, Statement stmt) {
        String sql = req.getParameter("q");
        stmt.executeQuery(sql);
    }
}
