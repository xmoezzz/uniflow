package demo.web;

import demo.app.*;
import javax.servlet.http.HttpServletRequest;

public class Controller {
    public void handle(HttpServletRequest request, UserService service) {
        var repo = service.current();
        String sql = request.getParameter("q");
        repo.query(sql);
    }
}
