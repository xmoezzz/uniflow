# 初始化失败时无法处理异常块中的错误

**漏洞描述:** 如果初始化失败，则无法处理异常块中的错误。

**非合规代码示例:**

```sql
DECLARE
  employee_name emp.name%TYPE := get_employee_name(id => 5);
BEGIN
  ...
END;
```

**合规解决方案:**

```sql
DECLARE
  employee_name emp.name%TYPE;
BEGIN
  employee_name := get_employee_name(id => 5);
  ...
END;
```