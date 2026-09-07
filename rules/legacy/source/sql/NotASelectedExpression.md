# 标题：**SQL中选择 distinct 和 order by 的常见问题**

## 概述

在 SQL 中，当使用选择 distinct 时，如果在排序条件中指定的值不在选择语句中，Oracle 会抛出异常 `ORA-01791: not a SELECTed expression`。

## 示例

以下是一个示例：

```
SELECT DISTINCT item.name
  FROM item
 ORDER BY item.group_id
```

在这个例子中，`item.id` 列没有在选择语句中，所以 Oracle 会抛出 ORA-01791。正确的版本应该是：

```
SELECT DISTINCT item.name, item.group_id
  FROM item
 ORDER BY item.group_id
```

如果选择语句中的列有别名，你也可以在排序条件中使用该别名：

```
-- 有效的查询
SELECT DISTINCT item.name AS full_name
  FROM item
 ORDER BY item.name;
    
SELECT DISTINCT item.name AS full_name
  FROM item
 ORDER BY full_name;
```

需要注意的是，直到 Oracle 11.2.0.4 版本，Oracle 接受了在 ORDER BY 中的部分错误值，例如：

```
SELECT DISTINCT UPPER(item.name) AS full_name, item.group_id
  FROM item
 ORDER BY item.name -- 应该为 "UPPER(item.name)" 或 "full_name"
```

你应该修复这些查询，以避免与较新版本的 Oracle 数据库兼容性问题。