# 字符串拼接与NULL值

在Oracle数据库中，将一个VARCHAR2类型的值与NULL值进行拼接时，不会产生任何操作结果。因此，为了确保正确性，应该将NULL值移除。

示例：

```sql
var := NVL(''||id, 'Empty');
```

你应该使用以下代码：

```sql
var := NVL(TO_CHAR(id), 'Empty');
```

# 隐式转换为VARCHAR2类型

与其他数据类型（如NUMBER、DATE等）拼接在一起时，若该其他数据类型为NULL，则会自动将其转换为VARCHAR2类型。如果这是预期的行为，可以使用TO\_CHAR函数将拼接操作显式地转换为字符串。

示例：

```sql
var := NVL('123' || NULL, '0');
```

你应该使用以下代码：

```sql
var := NVL(TO_CHAR(CASE WHEN NULL THEN 123 ELSE 0 END), '0');
```