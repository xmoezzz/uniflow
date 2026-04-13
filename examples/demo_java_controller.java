import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
import com.example.SafeSql;

class ExampleController {
    public void handle(HttpServletRequest req, Statement stmt) {
        String query = req.getParameter("q");
        String sanitized = SafeSql.escapeSql(query);
        String sql = sanitized;
        stmt.executeQuery(sql);
    }
}
