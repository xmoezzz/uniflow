import javax.servlet.http.HttpServletRequest;

class UserController {
    public String handle(HttpServletRequest req, UserService svc) {
        String user = req.getParameter("user");
        return svc.run(user);
    }
}
