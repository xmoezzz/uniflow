# SQL中的别名

在SQL中，别名是一个可选的特性，它可以在FROM子句中使用，以使表名更短，从而使SQL语句更易读。别名可以用于以下情况：

1. 当您计划在FROM子句中多次使用相同的表时（例如自连接）。
2. 当您想要通过别名来简化表名，使其更易于阅读。

然而，当别名被滥用时，可能会导致可读性降低。

## 非合规代码示例

```sql
SELECT a.id,
       b.id,
       b.name
  FROM employee a,
       dept b
 WHERE a.dept_id = b.id;
```

## 合规解决方案

```sql
SELECT employee.id,
       dept.id,
       dept.name
  FROM employee,
       dept
 WHERE employee.dept_id = dept.id;
```