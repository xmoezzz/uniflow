# Always specify the date format in TO\_DATE calls.

## Noncompliant Code Example

在非合规的代码示例中，我们没有指定日期格式。这可能导致在将字符串转换为日期时出现未知错误。

```sql
begin
  var := to_date('2015-01-01');
end;
```

## Compliant Solution

在合规的解决方案中，我们在调用`to_date`函数时指定了日期格式。这将确保日期正确解析，避免潜在的错误。

```sql
begin
  var := to_date('2015-01-01', 'YYYY-MM-DD');
end;
```

## 漏洞影响

该漏洞可能会导致在处理日期和时间数据时出现问题，例如无法正确比较日期、检索日期范围或执行时间敏感操作。

## 风险评估

此漏洞的影响取决于受到影响的系统使用的日期函数和处理数据的程序。如果使用的是不正确的日期格式，可能会导致数据丢失、错误或 incorrect 的时间计算。