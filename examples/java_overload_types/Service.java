package demo.app;
import demo.repo.UserRepo;
import javax.servlet.http.HttpServletRequest;
public class Service {
    private UserRepo repo;
    public String handle(HttpServletRequest req) {
        var sql = req.getParameter("q");
        return repo.query(sql);
    }
}
