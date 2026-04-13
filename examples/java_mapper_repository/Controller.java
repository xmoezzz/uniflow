package demo.web;

import demo.data.UserMapper;
import javax.servlet.http.HttpServletRequest;
import javax.persistence.EntityManager;

public class Controller {
    private UserMapper mapper;
    private EntityManager em;

    public String handle(HttpServletRequest req) {
        var name = req.getParameter("name");
        var hql = mapper.selectByName(name);
        em.createQuery(hql);
        return hql;
    }
}
