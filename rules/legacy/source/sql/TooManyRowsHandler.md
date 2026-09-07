# SQL中的过多行异常

在SQL中，当使用`SELECT INTO`语句时，如果查询结果集包含太多行，将抛出`TooManyRows`异常。在这个异常中，定义在`INTO`子句中的变量值将被设置为未定义。

## 不合规代码示例

下面是一个不合规的示例代码，当遇到`TooManyRows`异常时，它将返回`NULL`。

```sql
BEGIN
  SELECT empno
  INTO var
  FROM emp;
EXCEPTION
  WHEN too_many_rows THEN
    NULL;
END;
```

## 合规解决方案

下面是一个合规的解决方案，当遇到`TooManyRows`异常时，它将将变量`var`设置为`NULL`。

```sql
BEGIN
  SELECT empno
  INTO var
  FROM emp;
EXCEPTION
  WHEN too_many_rows THEN
    var := NULL;
END;
```