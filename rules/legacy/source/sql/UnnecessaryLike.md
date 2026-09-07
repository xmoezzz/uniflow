# 标题：**SQL LIKE 条件中的空字符串漏洞**

## 漏洞描述

在 SQL 中使用 LIKE 条件时，如果没有使用通配符（如 % 或 _），则可能存在问题。维护者可能会猜测是否是忘记了使用通配符，或者是作为等于测试。

## 非合规代码示例

```sql
if (last_name like 'Smith') ...
```

## 合规解决方案

```sql
if (last_name like 'Smith%') ...
```

或者

```sql
if (last_name = 'Smith') ...
```