# 使用内置函数COUNT与局部变量结合是误导性的，并且在大多数情况下它是一种编码错误。

不合规代码示例
--------------

```sql
DECLARE
  v_empno emp.empno%TYPE;
  ...
BEGIN
  
  -- 在此阶段，v_empno为空，因此这个COUNT总是返回0。
  SELECT COUNT(v_empno)
    INTO i
    FROM employee
   WHERE employee.deptno = v_deptno;
END;
```

合规解决方案
--------------

```sql
BEGIN
  SELECT COUNT(*)
    INTO i
    FROM employee
   WHERE employee.deptno = v_deptno;
END;
```