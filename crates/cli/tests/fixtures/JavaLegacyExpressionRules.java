class JavaLegacyExpressionRules {
    void run(javax.servlet.http.HttpServletRequest request,
             java.sql.Statement[] statements, boolean flag) {
        String query = flag ? (String) request.getQueryString() : "SELECT 1";
        statements[0].executeQuery(query); // tainted-sink
        statements[0].executeQuery("SELECT 1"); // safe-sink
    }
}
