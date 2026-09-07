## SQL 代码注入漏洞

### 漏洞描述

在 SQL 语句中，使用多个条件判断时，如果没有正确处理每个条件之间的逻辑关系，可能导致恶意用户通过构造特定的 SQL 语句，从而执行非法操作或获取敏感信息。

### 非合规代码示例

```sql
if condition1 then
  if condition2 then
    -- code
  end if;
end if;
```

### 合规解决方案

```sql
if condition1 and condition2 then
  -- code
end if;
```

### 漏洞影响

攻击者可以通过构造特殊的 SQL 语句，使得条件1和条件2同时满足，从而绕过正常的安全控制，达到非法操作或者获取敏感信息的目的。