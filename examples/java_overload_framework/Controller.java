package demo.app;

import javax.servlet.http.HttpServletRequest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;

public class Controller {
    private Repo repo;
    private EntityManager em;

    public void handle(HttpServletRequest req) {
        String user = req.getParameter("user");
        String sql = repo.current();
        Query q = em.createNativeQuery(sql + user);
        q.setParameter(1, user);
        q.getResultList();
        repo.current(1);
    }
}
