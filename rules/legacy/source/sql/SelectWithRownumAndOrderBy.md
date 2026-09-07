# SQL查询中的顺序问题

在SQL查询中，WHERE子句通常会在ORDER BY子句之前执行。然而，在以下示例中，情况并非如此：

```sql
DECLARE
  CURSOR recent_users IS
    SELECT user.name,
           user.creation_date
    FROM user
    WHERE ROWNUM <= 5
    ORDER BY user.creation_date DESC;
BEGIN
  ...
```

这个查询不会返回最后5个创建的用户。数据库在没有对用户进行任何排序的情况下过滤掉这些用户，然后在之后应用ORDER BY子句。正确的查询应该是：

```sql
DECLARE
  CURSOR recent_users IS
    SELECT name,
           creation_date
    FROM (SELECT user.name,
                   user.creation_date
              FROM user
             ORDER BY user.creation_date DESC)
    WHERE ROWNUM <= 5;
BEGIN
  ...
```