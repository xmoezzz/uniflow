# 漏洞名称：未来可能的VARCHAR数据类型分离

## 漏洞描述：
当前，VARCHAR和VARCHAR2数据类型是相同的。但是为了适应新兴的SQL标准，VARCHAR可能会在未来成为一种独立的数据类型。

## 漏洞分析：
字符(CHAR)数据类型与VARCHAR2没有优势，而且由于右填充值使得搜索变得更加困难。

## 代码示例：
```sql
declare
  var1 varchar(10); -- 不合规
  var2 char(10); -- 不合规
  
  var3 varchar2(10); -- 合规
begin
  null;
end;
```

## 解决方案：
避免使用不合规的varchar(10)，而是使用合规的varchar2(10)。