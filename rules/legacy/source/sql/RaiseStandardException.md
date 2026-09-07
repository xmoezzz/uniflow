# 标题：避免使用RAISE语句的函数重写

在上述代码中，我们观察到一个使用`RAISE TOO_MANY_ROWS`异常作为流程控制机制的情况。这个函数可以被重新编写以避免使用`RAISE`语句：

```sql
CREATE OR REPLACE FUNCTION group_has_users(id IN NUMBER) RETURN BOOLEAN IS
  number_of_users NUMBER;
BEGIN
  BEGIN
    SELECT COUNT(*)
      INTO number_of_users
      FROM user_group
     WHERE user_group.group_id = id;
  EXCEPTION
    WHEN OTHERS THEN
      number_of_users := 0;
  END;
  
  RETURN number_of_users > 0;
END;
```

在这个修改后的版本中，我们使用`SELECT COUNT(*)`来计算`user_group`表中满足条件（`group_id = id`）的行数，并将结果存储在变量`number_of_users`中。然后，我们直接返回`number_of_users`的值，而不是使用`RAISE TOO_MANY_ROWS`异常。这样就避免了使用`RAISE`语句。