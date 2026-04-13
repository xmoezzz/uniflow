class UserService {
    public String run(String user) {
        String sql = buildSql(user);
        java.sql.Statement stmt = null;
        stmt.executeQuery(sql);
        return sql;
    }

    public String buildSql(String user) {
        return user;
    }
}
