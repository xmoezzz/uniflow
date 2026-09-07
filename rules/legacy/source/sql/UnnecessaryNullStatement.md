# 空语句漏洞

## 漏洞描述

在 SQL 中，如果在同一级别的其他语句中出现一个空语句（NULL），那么这个空语句是无效的，应该将其删除。该漏洞可能会导致 SQL 注入攻击，使得攻击者可以执行 arbitrary SQL 代码。

## 非合规代码示例

```sql
BEGIN
  var := 1;
  NULL; -- 这个 NULL 语句可以被删除
END
```

## 合规解决方案

```sql
BEGIN
  var := 1;
END
```